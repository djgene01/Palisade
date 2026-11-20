using System.Globalization;
using Palisade.Core;

namespace Palisade.UI.Services;

public sealed record Device(string Name, string Address, string Mac, bool Online, Reservation? Reservation, FirewallRule? BlockRule)
{
    /// <summary>Pause and schedule settings, when this device has any.</summary>
    public DeviceAccess? Access { get; init; }
    /// <summary>What the device is called without a name from the owner: its fixed-address name or what it called itself.</summary>
    public string OwnName { get; init; } = "";
    public bool Renamed { get; init; }
    /// <summary>The company that made the device, when its hardware address tells us. Empty otherwise.</summary>
    public string Maker { get; init; } = "";
    /// <summary>True when the address is one the device invented for itself, which hides who made it.</summary>
    public bool MadeUpAddress { get; init; }
    /// <summary>The name it answers to on the home network, such as grans-tablet.home.arpa. Empty when it has none (yet).</summary>
    public string DnsName { get; init; } = "";
    /// <summary>True when neither the owner nor the device itself supplied a name.</summary>
    public bool Unnamed { get; init; }
    /// <summary>A guess at what the device is, used only to choose its picture.</summary>
    public DeviceType Type { get; init; }
    /// <summary>Set when this device was caught trying to reach a connection-sharing service in the last week.</summary>
    public RelaySighting? Relay { get; init; }
    /// <summary>Set when this device may reach only chosen sites.</summary>
    public DeviceLimit? Limit { get; init; }

    /// <summary>Device names go into config files, so reduce whatever the device called itself to letters, digits and dashes.</summary>
    public string SafeName
    {
        get
        {
            var name = System.Text.RegularExpressions.Regex.Replace(Name, "[^A-Za-z0-9]+", "-").Trim('-');
            if (name.Length > 40) name = name[..40].Trim('-');
            return name.Length == 0 || Unnamed ? $"device-{Mac.Replace(":", "")[^6..]}" : name;
        }
    }
}

/// <summary>One per browser session: the loaded config and live status, plus the single path for saving changes.</summary>
public sealed class FirewallState(IFirewallBackend backend, IMakerSource makers)
{
    public FirewallConfig? Config { get; private set; }
    public SystemStatus? Status { get; private set; }
    public IReadOnlyList<DhcpLease> Leases { get; private set; } = [];
    public UsageReport? Usage { get; private set; }
    public WifiStatus? Wifi { get; private set; }

    public async Task RefreshWifiAsync()
    {
        try { Wifi = await backend.GetWifiAsync(); }
        catch (Exception) { Wifi = null; }
        Changed?.Invoke();
    }

    public async Task<IReadOnlyList<ValidationIssue>> JoinWifiAsync(string ssid, string passphrase)
    {
        try
        {
            var result = await backend.SetWifiAsync(new WifiRequest { Ssid = ssid, Passphrase = passphrase });
            await RefreshWifiAsync();
            return result.Ok ? [] : result.Issues;
        }
        catch (Exception ex)
        {
            return [new("", Problem.Explain(ex, "The firewall did not answer while changing the Wi-Fi. If you are connected through that Wi-Fi, this is expected: reconnect and look again."))];
        }
    }
    public string? Error { get; private set; }

    public event Action? Changed;
    /// <summary>Raised after a change went live and is waiting for confirmation.</summary>
    public event Action? ApplyStarted;

    /// <summary>
    /// Forgets everything loaded so far. Needed when the backend now stands for a different firewall: a load that
    /// then fails must not leave the previous firewall's settings on screen, where a save would send them to this one.
    /// </summary>
    public void Reset()
    {
        (Config, Status, Leases, Usage, Wifi, Error) = (null, null, [], null, null, null);
        Changed?.Invoke();
    }

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
            Error = Problem.Explain(ex, "The firewall service is not answering.");
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
            Error = Problem.Explain(ex, "The firewall service is not answering.");
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
            return [new("", Problem.Explain(ex, "The firewall service is not answering, so nothing was changed.", nothingChanged: true))];
        }
        if (!result.Ok) return result.Issues;

        draft.SetupComplete = true;
        Config = draft;
        Changed?.Invoke();
        ApplyStarted?.Invoke();
        return [];
    }

    /// <summary>Saves pauses and schedules. Unlike other settings these take effect and stay without a confirmation step.</summary>
    public async Task<IReadOnlyList<ValidationIssue>> SaveAccessAsync(Action<List<DeviceAccess>> change)
    {
        if (Config is null) return [new("", "Settings have not loaded yet.")];
        try
        {
            // Start from the firewall's own copy, so a pause set in another window is not undone by this one.
            var access = (await backend.GetConfigAsync()).Access;
            change(access);
            var result = await backend.SetAccessAsync(access);
            if (!result.Ok) return result.Issues;
            Config.Access = access;
        }
        catch (Exception ex)
        {
            return [new("", Problem.Explain(ex, "The firewall service is not answering, so nothing was changed.", nothingChanged: true))];
        }
        Changed?.Invoke();
        return [];
    }

    /// <summary>Gives a device a name of the owner's choosing, or takes it away again when the name is empty.</summary>
    public async Task<IReadOnlyList<ValidationIssue>> RenameAsync(string mac, string name)
    {
        if (Config is null) return [new("", "Settings have not loaded yet.")];
        try
        {
            var names = (await backend.GetConfigAsync()).Names;
            names.RemoveAll(n => n.Mac == mac);
            if (name.Length > 0) names.Add(new DeviceName { Mac = mac, Name = name });
            var result = await backend.SetNamesAsync(names);
            if (!result.Ok) return result.Issues;
            Config.Names = names;
        }
        catch (Exception ex)
        {
            return [new("", Problem.Explain(ex, "The firewall service is not answering, so nothing was changed.", nothingChanged: true))];
        }
        Changed?.Invoke();
        return [];
    }

    /// <summary>Who made a device, when its hardware address tells, or empty.</summary>
    public string MakerOf(string mac) => makers.Find(mac) ?? "";

    /// <summary>Devices waiting for approval while Zero Trust is on, newest first.</summary>
    public IReadOnlyList<HeldDevice> Waiting => Config?.ZeroTrust.Enabled == true ? Status?.HeldDevices ?? [] : [];

    /// <summary>Switches Zero Trust on or off. Like other changes it goes live and waits for confirmation.</summary>
    public Task<IReadOnlyList<ValidationIssue>> SetZeroTrustAsync(ZeroTrustRequest request) =>
        RunApprovalAsync(() => backend.SetZeroTrustAsync(request));

    /// <summary>
    /// Approves, blocks, removes or unblocks one device. Letting one in is immediate; taking access away
    /// from an approved device waits for confirmation, which the page frame then looks after.
    /// </summary>
    public Task<IReadOnlyList<ValidationIssue>> ChangeApprovalAsync(ApprovalAction action, string mac, string name = "") =>
        RunApprovalAsync(() => backend.ChangeApprovalAsync(new ApprovalChange { Action = action, Mac = mac, Name = name }));

    /// <summary>Switches the VPN on or off, or changes its settings. Waits for confirmation, which the page frame looks after.</summary>
    public Task<IReadOnlyList<ValidationIssue>> SetVpnAsync(VpnRequest request) => RunApprovalAsync(() => backend.SetVpnAsync(request));

    /// <summary>Shuts a VPN device out, at once and for good.</summary>
    public Task<IReadOnlyList<ValidationIssue>> RemoveVpnDeviceAsync(string id) => RunApprovalAsync(() => backend.RemoveVpnDeviceAsync(id));

    /// <summary>Lets a new device in and returns its settings for the WireGuard app, this once.</summary>
    public async Task<VpnDeviceResult> AddVpnDeviceAsync(VpnDeviceRequest request)
    {
        VpnDeviceResult result;
        try { result = await backend.AddVpnDeviceAsync(request); }
        catch (Exception ex)
        {
            return new VpnDeviceResult { Issues = [new("", Problem.Explain(ex, "The firewall service is not answering, so no device was added.", nothingChanged: true))] };
        }
        if (result.Ok) await LoadAsync();
        return result;
    }

    public Task<VpnStatus> GetVpnAsync() => backend.GetVpnAsync();
    public Task<ReachabilityReport> CheckVpnAsync() => backend.CheckVpnAsync();

    private async Task<IReadOnlyList<ValidationIssue>> RunApprovalAsync(Func<Task<ApplyResult>> call)
    {
        ApplyResult result;
        try { result = await call(); }
        catch (Exception ex)
        {
            return [new("", Problem.Explain(ex, "The firewall service is not answering, so nothing was changed.", nothingChanged: true))];
        }
        if (!result.Ok) return result.Issues;
        // Reload from the firewall: it decides the lists, including who was approved when the mode came on.
        await LoadAsync();
        if (result.ConfirmWithinSeconds > 0) ApplyStarted?.Invoke();
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
        // A device in the holding zone is waiting for approval, not one of the household's: it is listed there instead.
        foreach (var lease in Leases.Where(l => !ZeroTrustPlan.InHoldingZone(Config.ZeroTrust, l.Address)))
        {
            var reservation = Config.Dhcp.Reservations.FirstOrDefault(r => r.Mac == lease.Mac);
            devices.Add(new Device(reservation?.Name ?? lease.Hostname ?? "Unnamed device", lease.Address, lease.Mac, true, reservation,
                Config.Rules.FirstOrDefault(r => IsDeviceBlock(r, lease.Address))));
        }
        foreach (var r in Config.Dhcp.Reservations.Where(r => Leases.All(l => l.Mac != r.Mac)))
            devices.Add(new Device(r.Name, r.Address, r.Mac, false, r, Config.Rules.FirstOrDefault(rule => IsDeviceBlock(rule, r.Address))));
        // A paused or scheduled device that is away has no address, but must stay listed so it can be resumed.
        foreach (var a in Config.Access.Where(a => devices.All(d => d.Mac != a.Mac)))
            devices.Add(new Device(a.Name, "", a.Mac, false, null, null));
        return [.. devices.Select(d =>
        {
            var given = Config.Names.FirstOrDefault(n => n.Mac == d.Mac)?.Name;
            var maker = makers.Find(d.Mac) ?? "";
            var unnamed = d.Name == "Unnamed device";
            // A device that never said what it is called is at least told apart by who made it.
            var own = unnamed && maker.Length > 0 ? $"{maker} device" : d.Name;
            return d with
            {
                Access = Config.Access.FirstOrDefault(a => a.Mac == d.Mac), OwnName = own, Name = given ?? own, Renamed = given is not null,
                Limit = Config.Limits.FirstOrDefault(l => l.Mac == d.Mac),
                Relay = Status?.RelayDevices.FirstOrDefault(r => r.Mac == d.Mac),
                Type = DeviceKind.Guess($"{given} {d.Name}", maker),
                Maker = maker, MadeUpAddress = Core.Maker.IsMadeUp(d.Mac), Unnamed = unnamed,
                DnsName = Status?.Names.FirstOrDefault(n => n.Mac == d.Mac)?.Name is { } dns ? $"{dns}.{NamePlan.Domain}" : "",
            };
        })];
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
