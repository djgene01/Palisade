using System.Globalization;
using Palisade.Core;

namespace Palisade.Web.Services;

public sealed record Device(string Name, string Address, string Mac, bool Online, Reservation? Reservation, FirewallRule? BlockRule)
{
    /// <summary>Device names go into config files, so reduce whatever the device called itself to letters, digits and dashes.</summary>
    public string SafeName
    {
        get
        {
            var name = System.Text.RegularExpressions.Regex.Replace(Name, "[^A-Za-z0-9]+", "-").Trim('-');
            if (name.Length > 40) name = name[..40].Trim('-');
            return name.Length == 0 || Name == "Unnamed device" ? $"device-{Mac.Replace(":", "")[^6..]}" : name;
        }
    }
}

/// <summary>One per browser session: the loaded config and live status, plus the single path for saving changes.</summary>
public sealed class FirewallState(IFirewallBackend backend)
{
    public FirewallConfig? Config { get; private set; }
    public SystemStatus? Status { get; private set; }
    public IReadOnlyList<DhcpLease> Leases { get; private set; } = [];
    public UsageReport? Usage { get; private set; }
    public string? Error { get; private set; }

    public event Action? Changed;
    /// <summary>Raised after a change went live and is waiting for confirmation.</summary>
    public event Action? ApplyStarted;

    public async Task LoadAsync()
    {
        try
        {
            Config = await backend.GetConfigAsync();
            Status = await backend.GetStatusAsync();
            Leases = await backend.GetLeasesAsync();
            Error = null;
        }
        catch (Exception ex)
        {
            Error = $"The firewall service is not answering. ({ex.Message})";
        }
        Changed?.Invoke();
    }

    public async Task RefreshStatusAsync()
    {
        try
        {
            Status = await backend.GetStatusAsync();
            Leases = await backend.GetLeasesAsync();
            Usage = await backend.GetUsageAsync();
            Error = null;
        }
        catch (Exception ex)
        {
            Error = $"The firewall service is not answering. ({ex.Message})";
        }
        Changed?.Invoke();
    }

    /// <summary>Applies a change to a copy of the config. Returns the problems to show, or none when it went live.</summary>
    public async Task<IReadOnlyList<ValidationIssue>> SaveAsync(Action<FirewallConfig> change)
    {
        if (Config is null) return [new("", "Settings have not loaded yet.")];
        var draft = Config.Clone();
        change(draft);
        ApplyResult result;
        try
        {
            result = await backend.ApplyAsync(draft);
        }
        catch (Exception ex)
        {
            return [new("", $"The firewall service is not answering, so nothing was changed. ({ex.Message})")];
        }
        if (!result.Ok) return result.Issues;

        draft.SetupComplete = true;
        Config = draft;
        Changed?.Invoke();
        ApplyStarted?.Invoke();
        return [];
    }

    public Task ConfirmAsync() => backend.ConfirmAsync();

    public async Task RevertAsync()
    {
        await backend.RevertAsync();
        await LoadAsync();
    }

    public InterfaceStatus? Wan => Status?.Interfaces.FirstOrDefault(i => i.Name == Config?.WanInterface);
    public InterfaceStatus? Lan => Status?.Interfaces.FirstOrDefault(i => i.Name == Config?.LanInterface);

    public static bool IsDeviceBlock(FirewallRule r, string address) =>
        r is { Action: RuleAction.Block, Direction: RuleDirection.Outgoing, Destination: "", Protocol: Protocol.Any, Enabled: true } && r.Source == address;

    /// <summary>Devices that hold an address now, followed by ones with a fixed address that are currently away.</summary>
    public List<Device> Devices()
    {
        if (Config is null) return [];
        var devices = new List<Device>();
        foreach (var lease in Leases)
        {
            var reservation = Config.Dhcp.Reservations.FirstOrDefault(r => r.Mac == lease.Mac);
            devices.Add(new Device(reservation?.Name ?? lease.Hostname ?? "Unnamed device", lease.Address, lease.Mac, true, reservation,
                Config.Rules.FirstOrDefault(r => IsDeviceBlock(r, lease.Address))));
        }
        foreach (var r in Config.Dhcp.Reservations.Where(r => Leases.All(l => l.Mac != r.Mac)))
            devices.Add(new Device(r.Name, r.Address, r.Mac, false, r, Config.Rules.FirstOrDefault(rule => IsDeviceBlock(rule, r.Address))));
        return devices;
    }
}

public static class Fmt
{
    public static string Rate(double bytesPerSecond)
    {
        var bits = bytesPerSecond * 8;
        return bits >= 1_000_000 ? $"{(bits / 1_000_000).ToString("0.0", CultureInfo.InvariantCulture)} Mbit/s"
            : bits >= 1_000 ? $"{(bits / 1_000).ToString("0", CultureInfo.InvariantCulture)} kbit/s"
            : $"{bits.ToString("0", CultureInfo.InvariantCulture)} bit/s";
    }

    public static string Bytes(long bytes) => bytes switch
    {
        >= 1_000_000_000 => $"{(bytes / 1e9).ToString("0.0", CultureInfo.InvariantCulture)} GB",
        >= 1_000_000 => $"{(bytes / 1e6).ToString(bytes >= 100_000_000 ? "0" : "0.0", CultureInfo.InvariantCulture)} MB",
        >= 1_000 => $"{(bytes / 1e3).ToString("0", CultureInfo.InvariantCulture)} kB",
        _ => $"{bytes.ToString(CultureInfo.InvariantCulture)} bytes",
    };

    public static string Uptime(long seconds)
    {
        var t = TimeSpan.FromSeconds(seconds);
        return t.TotalDays >= 1 ? $"{(int)t.TotalDays} d {t.Hours} h" : t.TotalHours >= 1 ? $"{t.Hours} h {t.Minutes} min" : $"{Math.Max(1, t.Minutes)} min";
    }

    public static string Plural(int count, string one, string many) => count == 1 ? $"1 {one}" : $"{count} {many}";

    public static string FilterLevel(FilterLevel level) => level switch
    {
        Core.FilterLevel.Security => "Harmful sites",
        Core.FilterLevel.Adult => "Harmful and adult sites",
        Core.FilterLevel.Family => "Strict, for children",
        _ => "No filtering",
    };

    public static string FilterLevelDetail(FilterLevel level) => level switch
    {
        Core.FilterLevel.Security => "Blocks sites known for viruses, scams and stealing passwords.",
        Core.FilterLevel.Adult => "Also blocks pornography and other adult sites.",
        Core.FilterLevel.Family => "Also locks Google, Bing and YouTube into safe search, and blocks VPN sites and mixed sites such as Reddit.",
        _ => "Every site opens, apart from the ones you block yourself below.",
    };

    public static string Protocol(Protocol p) => p switch
    {
        Core.Protocol.Tcp => "TCP",
        Core.Protocol.Udp => "UDP",
        Core.Protocol.TcpUdp => "TCP and UDP",
        Core.Protocol.Icmp => "Ping (ICMP)",
        _ => "Any kind",
    };

    /// <summary>Suggests a DHCP range inside a network: .100 to .200 when there is room, otherwise the upper half.</summary>
    public static (string Start, string End) SuggestRange(Ip4 lan, int prefix)
    {
        var network = lan.Network(prefix).Value;
        var last = lan.Broadcast(prefix).Value - 1;
        var (from, to) = last - network >= 253 ? (network + 100, network + 200) : (network + (last - network) / 2 + 1, last);
        if (lan.Value >= from && lan.Value <= to) from = lan.Value + 1;
        return (new Ip4(from).ToString(), new Ip4(to).ToString());
    }
}
