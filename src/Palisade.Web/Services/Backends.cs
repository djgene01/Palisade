using System.Net.Http.Json;
using System.Net.Sockets;
using Palisade.Core;

namespace Palisade.Web.Services;

/// <summary>Talks to the root agent over its Unix socket. This is the web UI's only route to the system.</summary>
public sealed class AgentClient : IFirewallBackend, IUpdates, ITrafficWatch, IDnsControl, IDisposable
{
    public async Task<ApplyResult> FlushDnsAsync(CancellationToken ct = default)
    {
        using var response = await _http.PostAsync("dns/flush", null, ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<ApplyResult>(PalisadeJson.Options, ct))!;
    }

    public async Task<WatchReport> WatchAsync(WatchRequest request, CancellationToken ct = default)
    {
        using var response = await _http.PostAsJsonAsync("watch", request, PalisadeJson.Options, ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<WatchReport>(PalisadeJson.Options, ct))!;
    }

    public async Task<UpdateStatus> GetUpdateAsync(CancellationToken ct = default) =>
        (await _http.GetFromJsonAsync<UpdateStatus>("update", PalisadeJson.Options, ct))!;

    public async Task<UpdateStatus> SetUpdateAsync(UpdateSettings settings, CancellationToken ct = default)
    {
        using var response = await _http.PostAsJsonAsync("update/settings", settings, PalisadeJson.Options, ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<UpdateStatus>(PalisadeJson.Options, ct))!;
    }

    public async Task<UpdateStatus> CheckUpdateAsync(bool install, CancellationToken ct = default)
    {
        // Downloading a release can take minutes on a slow line, far longer than any other call.
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var response = await _http.PostAsync(install ? "update/install" : "update/check", null, limit.Token);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<UpdateStatus>(PalisadeJson.Options, ct))!;
    }

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
        _http = new HttpClient(handler) { BaseAddress = new Uri("http://agent/"), Timeout = TimeSpan.FromSeconds(60) };
    }

    public async Task<SystemStatus> GetStatusAsync(CancellationToken ct = default) =>
        (await _http.GetFromJsonAsync<SystemStatus>("status", PalisadeJson.Options, ct))!;

    public async Task<FirewallConfig> GetConfigAsync(CancellationToken ct = default) =>
        (await _http.GetFromJsonAsync<FirewallConfig>("config", PalisadeJson.Options, ct))!;

    public async Task<IReadOnlyList<DhcpLease>> GetLeasesAsync(CancellationToken ct = default) =>
        (await _http.GetFromJsonAsync<List<DhcpLease>>("leases", PalisadeJson.Options, ct))!;

    public async Task<UsageReport> GetUsageAsync(CancellationToken ct = default) =>
        (await _http.GetFromJsonAsync<UsageReport>("usage", PalisadeJson.Options, ct))!;

    public async Task<WifiStatus> GetWifiAsync(CancellationToken ct = default) =>
        (await _http.GetFromJsonAsync<WifiStatus>("wifi", PalisadeJson.Options, ct))!;

    public async Task<ApplyResult> SetWifiAsync(WifiRequest request, CancellationToken ct = default)
    {
        using var response = await _http.PostAsJsonAsync("wifi", request, PalisadeJson.Options, ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<ApplyResult>(PalisadeJson.Options, ct))!;
    }

    public async Task<ApplyResult> SetNamesAsync(List<DeviceName> names, CancellationToken ct = default)
    {
        using var response = await _http.PostAsJsonAsync("names", names, PalisadeJson.Options, ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<ApplyResult>(PalisadeJson.Options, ct))!;
    }

    public async Task<ApplyResult> SetAccessAsync(List<DeviceAccess> access, CancellationToken ct = default)
    {
        using var response = await _http.PostAsJsonAsync("access", access, PalisadeJson.Options, ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<ApplyResult>(PalisadeJson.Options, ct))!;
    }

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
