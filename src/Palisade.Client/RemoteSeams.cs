using System.Collections.Concurrent;
using Palisade.Core;
using Palisade.UI.Services;

namespace Palisade.Client;

/// <summary>
/// The app's answer to "can a brand-new connection still reach the firewall?" after a change. It opens a fresh
/// connection for every try, because the one already open keeps working even when a new rule would block the next.
/// </summary>
public sealed class RemoteProbe(FirewallLink link) : IConnectionProbe
{
    private const int Attempts = 3;
    private static readonly TimeSpan PerAttempt = TimeSpan.FromSeconds(2.5);
    private static readonly TimeSpan BetweenAttempts = TimeSpan.FromMilliseconds(700);

    public async Task<bool> CanReachAsync(CancellationToken ct = default)
    {
        for (var attempt = 0; attempt < Attempts; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            using var http = new HttpClient(PinnedConnection.Handler(link.Pin, freshConnections: true)) { BaseAddress = link.Address.BaseUri, Timeout = PerAttempt };
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{AppContract.Prefix}/ping");
            request.Headers.ConnectionClose = true;
            try
            {
                using var response = await http.SendAsync(request, ct);
                if (response.IsSuccessStatusCode) return true;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested) { }
            await Task.Delay(BetweenAttempts, ct);
        }
        return false;
    }

    /// <summary>
    /// Only the setup page asks this, to tell whether someone is on the internet side. Setup happens in the
    /// browser, before any phone can be linked, so the app never needs it.
    /// </summary>
    public Task<string> ClientAddressAsync(CancellationToken ct = default) => Task.FromResult("");
}

/// <summary>
/// Device makers, asked from the firewall, which looks them up and remembers them. The screens need an answer
/// at once, so this answers from what it already knows and fetches the rest in the background; the next refresh
/// of the page then shows them.
/// </summary>
public sealed class RemoteMakers(RemoteBackend backend) : IMakerSource
{
    private static readonly TimeSpan RetryAfter = TimeSpan.FromMinutes(2);

    private readonly ConcurrentDictionary<string, string?> _known = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _asked = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<string> _wanted = new();
    private int _fetching;

    /// <summary>Raised after new makers arrived, so a page can refresh and show them.</summary>
    public event Action? Learned;

    public string? Find(string mac)
    {
        if (_known.TryGetValue(mac, out var maker)) return maker;
        var now = DateTimeOffset.UtcNow;
        if (_asked.TryGetValue(mac, out var at) && now - at < RetryAfter) return null;
        _asked[mac] = now;
        _wanted.Enqueue(mac);
        if (Interlocked.CompareExchange(ref _fetching, 1, 0) == 0) _ = FetchAsync();
        return null;
    }

    private async Task FetchAsync()
    {
        try
        {
            // A moment's wait gathers every device on the page into one request.
            await Task.Delay(150);
            var batch = new List<string>();
            while (batch.Count < AppContract.MakersPerRequest && _wanted.TryDequeue(out var mac)) batch.Add(mac);
            if (batch.Count == 0) return;
            var answers = await backend.GetMakersAsync(batch);
            var learned = false;
            foreach (var (mac, maker) in answers)
            {
                // The firewall says null while its own lookup is still under way: ask again later.
                if (maker is null) continue;
                _known[mac] = maker;
                learned = true;
            }
            if (learned) Learned?.Invoke();
        }
        catch (FirewallException) { /* Out of reach for now; the next Find after the retry time asks again. */ }
        finally
        {
            Volatile.Write(ref _fetching, 0);
            if (!_wanted.IsEmpty && Interlocked.CompareExchange(ref _fetching, 1, 0) == 0) _ = FetchAsync();
        }
    }
}
