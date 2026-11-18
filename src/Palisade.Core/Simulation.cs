namespace Palisade.Core;

/// <summary>
/// A pretend network for trying the interface on a development machine. It changes nothing on the
/// host, and the UI shows a permanent "demo mode" banner whenever it is in use.
/// </summary>
public sealed class SimulatedPlatform : ISystemPlatform
{
    private readonly DateTimeOffset _started = DateTimeOffset.UtcNow;
    private readonly Random _random = new();
    private DateTimeOffset _lastSample = DateTimeOffset.UtcNow;
    private long _rx = 48_000_000, _tx = 9_000_000;
    private FirewallConfig? _applied;
    private string _wifi = "Demo Wi-Fi";
    private readonly UsageTracker _usage = new(DateTimeOffset.UtcNow);
    private readonly Dictionary<string, (long Down, long Up)> _counters = [];
    private DateTimeOffset _usageAt = DateTimeOffset.UtcNow;

    public Task<IReadOnlyList<string>> CheckAsync(FirewallConfig config, GeneratedFiles files, CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<string>>([]);

    public Task ApplyAsync(FirewallConfig config, GeneratedFiles files, CancellationToken ct)
    {
        _applied = config.Clone();
        return Task.CompletedTask;
    }

    public Task SetAccessAsync(IReadOnlyList<DeviceAccess> access, CancellationToken ct) => Task.CompletedTask;

    /// <summary>A phone nobody has approved, which turns up in the demo once Zero Trust is on.</summary>
    public const string StrangerMac = "52:54:00:bb:00:66";

    public Task SetApprovalsAsync(FirewallConfig live, CancellationToken ct)
    {
        if (_applied is not null) _applied.ZeroTrust = live.Clone().ZeroTrust;
        return Task.CompletedTask;
    }

    // The demo's own devices all come in through leases, so there is nothing extra to hear about.
    public Task<IReadOnlyList<string>> GetNeighboursAsync(FirewallConfig live, CancellationToken ct) => Task.FromResult<IReadOnlyList<string>>([]);

    private static bool StrangerWaiting(FirewallConfig c) =>
        c.ZeroTrust.Enabled && c.ZeroTrust.Approved.All(d => d.Mac != StrangerMac) && c.ZeroTrust.Blocked.All(d => d.Mac != StrangerMac);

    public Task<WifiStatus> GetWifiAsync(CancellationToken ct) =>
        Task.FromResult(new WifiStatus { Interface = "wlp3s0", Ssid = _wifi, Connected = true, Address = "10.0.0.88" });

    public async Task<ApplyResult> SetWifiAsync(WifiRequest request, CancellationToken ct)
    {
        await Task.Delay(1500, ct);
        // The pretend network refuses one name, so the "could not join" message can be seen in the demo.
        if (request.Ssid == "wrong") return ApplyResult.Failed("The firewall could not join that Wi-Fi network. Check the name and the password. The previous Wi-Fi settings are back in use.");
        _wifi = request.Ssid;
        return new ApplyResult { Ok = true };
    }

    public Task ClearAsync(CancellationToken ct)
    {
        _applied = null;
        return Task.CompletedTask;
    }

    public Task<SystemStatus> GetStatusAsync(FirewallConfig active, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var seconds = (now - _lastSample).TotalSeconds;
        _lastSample = now;
        _rx += (long)(seconds * _random.Next(40_000, 900_000));
        _tx += (long)(seconds * _random.Next(8_000, 160_000));

        var lanAddresses = _applied is null ? new List<string>() : [$"{_applied.LanAddress}/{_applied.LanPrefix}"];
        return Task.FromResult(new SystemStatus
        {
            Hostname = "palisade-demo",
            // The demo's unnamed device plays the part of a box that carries relay software.
            RelayDevices = active.Filter.BlockRelays ? [new RelaySighting { Mac = "52:54:00:aa:00:04", Attempts = 212, LastSeen = now.AddMinutes(-3) }] : [],
            // With Zero Trust on, the stranger sits in the holding zone, knocking on a few doors.
            HeldDevices = StrangerWaiting(active)
                ? [new HeldDevice
                {
                    Mac = StrangerMac, Address = ZeroTrustPlan.HoldingPool(active.ZeroTrust).First.ToString(), Hostname = "android-7f3a",
                    FirstSeen = _started.AddMinutes(-2), LastSeen = now.AddSeconds(-20), Attempts = 47,
                    Flows =
                    [
                        new HeldFlow { Address = active.ZeroTrust.HoldingAddress, Protocol = "udp", Port = 53, Packets = 31, LastSeen = now.AddSeconds(-20) },
                        new HeldFlow { Address = "142.250.180.4", Protocol = "tcp", Port = 443, Packets = 12, LastSeen = now.AddMinutes(-1) },
                        new HeldFlow { Address = "3.120.181.40", Protocol = "tcp", Port = 8883, Packets = 4, LastSeen = now.AddMinutes(-2) },
                    ],
                }]
                : [],
            UptimeSeconds = (long)(now - _started).TotalSeconds,
            Simulated = true,
            FirewallActive = _applied is not null,
            DhcpRunning = _applied is not null,
            InternetReachable = true,
            Interfaces =
            [
                new("enp1s0", "52:54:00:00:00:01", true, ["10.0.0.57/24"], _rx, _tx),
                new("enp2s0", "52:54:00:00:00:02", true, lanAddresses, _tx, _rx),
                new("wlp3s0", "52:54:00:00:00:03", true, ["10.0.0.88/24"], 0, 0) { IsWireless = true },
            ],
        });
    }

    public async Task<UsageReport> GetUsageAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var seconds = (now - _usageAt).TotalSeconds;
        if (seconds < 1.5) return _usage.Report(now);
        _usageAt = now;
        // Each pretend device has its own appetite, so the list has a clear order to look at.
        var leases = await GetLeasesAsync(ct);
        for (var i = 0; i < leases.Count; i++)
        {
            var before = _counters.GetValueOrDefault(leases[i].Address);
            var busy = i == 2 || _random.Next(4) > 0;
            var down = busy ? (long)(seconds * _random.Next(20_000, 400_000) * (i == 2 ? 6 : 1.0 / (i + 1))) : 0;
            _counters[leases[i].Address] = (before.Down + down, before.Up + down / _random.Next(8, 30));
        }
        _usage.Record(now, new Dictionary<string, (long, long)>(_counters));
        return _usage.Report(now);
    }

    public Task<IReadOnlyList<DhcpLease>> GetLeasesAsync(CancellationToken ct)
    {
        if (_applied is not { Dhcp.Enabled: true } config || !Ip4.TryParse(config.Dhcp.RangeStart, out var start))
            return Task.FromResult<IReadOnlyList<DhcpLease>>([]);

        var expires = DateTimeOffset.UtcNow.AddHours(config.Dhcp.LeaseHours);
        string?[] names = ["demo-laptop", "demo-phone", "demo-tv", null];
        var leases = names.Select((name, i) =>
        {
            var mac = $"52:54:00:aa:00:{i + 1:x2}";
            var reserved = config.Dhcp.Reservations.FirstOrDefault(r => r.Mac == mac);
            return new DhcpLease(expires, mac, reserved?.Address ?? new Ip4(start.Value + (uint)i).ToString(), name);
        }).ToList();
        // The stranger: in the holding zone while it waits, on the home network once it is approved.
        if (StrangerWaiting(config))
            leases.Add(new DhcpLease(DateTimeOffset.UtcNow.AddMinutes(2), StrangerMac, ZeroTrustPlan.HoldingPool(config.ZeroTrust).First.ToString(), "android-7f3a"));
        else if (config.ZeroTrust.Enabled && config.ZeroTrust.Approved.Any(d => d.Mac == StrangerMac))
            leases.Add(new DhcpLease(expires, StrangerMac, new Ip4(start.Value + 20).ToString(), "android-7f3a"));
        return Task.FromResult<IReadOnlyList<DhcpLease>>(leases);
    }
}

/// <summary>Stands in for the updater in the demo: it remembers the switch and pretends a newer release exists.</summary>
public sealed class SimulatedUpdates : IUpdates
{
    private readonly UpdateStatus _status = new() { Current = "v1.0" };

    public Task<UpdateStatus> GetUpdateAsync(CancellationToken ct = default) => Task.FromResult(_status);

    public Task<UpdateStatus> SetUpdateAsync(UpdateSettings settings, CancellationToken ct = default)
    {
        _status.Auto = settings.Auto;
        if (settings.Token is not null) _status.HasToken = settings.Token.Length > 0;
        return Task.FromResult(_status);
    }

    public Task<UpdateStatus> CheckUpdateAsync(bool install, CancellationToken ct = default)
    {
        _status.CheckedAt = DateTimeOffset.UtcNow;
        _status.Latest = "v1.1";
        if (install) _status.Current = "v1.1";
        return Task.FromResult(_status);
    }
}

/// <summary>Stands in for a real watch in the demo, with a made-up list after a short wait.</summary>
public sealed class SimulatedWatch : ITrafficWatch, IDnsControl
{
    public Task<ApplyResult> FlushDnsAsync(CancellationToken ct = default) => Task.FromResult(new ApplyResult { Ok = true });

    public async Task<WatchReport> WatchAsync(WatchRequest request, CancellationToken ct = default)
    {
        await Task.Delay(TimeSpan.FromSeconds(3), ct);
        return new WatchReport
        {
            Address = request.Address, Seconds = WatchPlan.Seconds(request.Seconds),
            Flows =
            [
                new("203.0.113.40", "tcp", 443, 48_200, 9_340_000) { Name = "upload.example-cloud.com" },
                new("198.51.100.7", "tcp", 8883, 12_400, 61_000),
                new("192.0.2.53", "udp", 123, 180, 180) { Name = "time.example.net" },
            ],
        };
    }
}
