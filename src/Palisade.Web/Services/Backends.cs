using System.Net.Http.Json;
using System.Net.Sockets;
using Palisade.Core;

namespace Palisade.Web.Services;

/// <summary>Talks to the root agent over its Unix socket. This is the web UI's only route to the system.</summary>
public sealed class AgentClient : IFirewallBackend, IDisposable
{
    private readonly HttpClient _http;

    public AgentClient(string socketPath)
    {
        var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (_, ct) =>
            {
                var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                try
                {
                    await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), ct);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };
        _http = new HttpClient(handler) { BaseAddress = new Uri("http://agent/"), Timeout = TimeSpan.FromSeconds(30) };
    }

    public async Task<SystemStatus> GetStatusAsync(CancellationToken ct = default) =>
        (await _http.GetFromJsonAsync<SystemStatus>("status", PalisadeJson.Options, ct))!;

    public async Task<FirewallConfig> GetConfigAsync(CancellationToken ct = default) =>
        (await _http.GetFromJsonAsync<FirewallConfig>("config", PalisadeJson.Options, ct))!;

    public async Task<IReadOnlyList<DhcpLease>> GetLeasesAsync(CancellationToken ct = default) =>
        (await _http.GetFromJsonAsync<List<DhcpLease>>("leases", PalisadeJson.Options, ct))!;

    public async Task<UsageReport> GetUsageAsync(CancellationToken ct = default) =>
        (await _http.GetFromJsonAsync<UsageReport>("usage", PalisadeJson.Options, ct))!;

    public async Task<ApplyResult> ApplyAsync(FirewallConfig config, CancellationToken ct = default)
    {
        using var response = await _http.PostAsJsonAsync("config/apply", config, PalisadeJson.Options, ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<ApplyResult>(PalisadeJson.Options, ct))!;
    }

    public async Task ConfirmAsync(CancellationToken ct = default) =>
        (await _http.PostAsync("config/confirm", null, ct)).EnsureSuccessStatusCode();

    public async Task RevertAsync(CancellationToken ct = default) =>
        (await _http.PostAsync("config/revert", null, ct)).EnsureSuccessStatusCode();

    public void Dispose() => _http.Dispose();
}

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
            UptimeSeconds = (long)(now - _started).TotalSeconds,
            Simulated = true,
            FirewallActive = _applied is not null,
            DhcpRunning = _applied is not null,
            InternetReachable = true,
            Interfaces =
            [
                new("enp1s0", "52:54:00:00:00:01", true, ["10.0.0.57/24"], _rx, _tx),
                new("enp2s0", "52:54:00:00:00:02", true, lanAddresses, _tx, _rx),
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
        return Task.FromResult<IReadOnlyList<DhcpLease>>(leases);
    }
}
