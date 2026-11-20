using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using Palisade.Core;

namespace Palisade.Agent;

/// <summary>
/// The VPN: a WireGuard interface the agent makes and keeps in step with the config. Keys never appear in a command
/// line, a log, the config or the generated files: they go through standard input, and files that hold one are
/// created readable by root alone.
/// </summary>
public sealed partial class LinuxPlatform
{
    private const UnixFileMode RootOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private static readonly HttpClient Outside = new() { Timeout = TimeSpan.FromSeconds(8) };
    private ReachabilityReport? _reach;
    private string DuckDnsFile => Path.Combine(dataDirectory, "duckdns.json");
    private string _duckResult = "";
    private string _duckAddress = "";
    private DateTimeOffset _duckAt;

    // Tests point this at their own stand-in, to see every outcome; a real firewall always asks Cloudflare.
    private static string TraceUrl => Environment.GetEnvironmentVariable("PALISADE_TRACE_URL") is { Length: > 0 } url ? url : VpnPlan.TraceUrl;

    public async Task<ReachabilityReport> CheckReachabilityAsync(FirewallConfig live, CancellationToken ct)
    {
        var port = WanAddress(live.WanInterface);
        string? seen = null;
        if (port.Length > 0)
        {
            try { seen = VpnPlan.ParseTrace(await Outside.GetStringAsync(TraceUrl, ct)); }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException) { logger.LogInformation("Asking which address the internet sees failed: {Message}", ex.Message); }
        }
        return _reach = VpnPlan.Check(port, seen, DateTimeOffset.UtcNow);
    }

    /// <summary>The internet port's own IPv4 address, the first global one.</summary>
    private static string WanAddress(string wan) =>
        NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Name == wan)?.GetIPProperties().UnicastAddresses
            .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork && !System.Net.IPAddress.IsLoopback(a.Address))?.Address.ToString() ?? "";

    public async Task<(string Private, string Public)> NewVpnKeysAsync(CancellationToken ct)
    {
        var made = await RunWithInputAsync("wg", ["genkey"], "", ct);
        var privateKey = made.Output.Trim();
        if (made.ExitCode != 0 || !VpnPlan.IsKey(privateKey)) throw new InvalidOperationException("WireGuard could not make a key. Is wireguard-tools installed?");
        return (privateKey, await PublicKeyAsync(privateKey, ct));
    }

    private async Task<string> PublicKeyAsync(string privateKey, CancellationToken ct)
    {
        var derived = await RunWithInputAsync("wg", ["pubkey"], privateKey + "\n", ct);
        var publicKey = derived.Output.Trim();
        return derived.ExitCode == 0 && VpnPlan.IsKey(publicKey) ? publicKey : throw new InvalidOperationException("WireGuard could not read a key.");
    }

    /// <summary>The firewall's own key, made the first time and kept for good: every issued device config depends on it.</summary>
    private async Task<string> ServerPrivateKeyAsync(CancellationToken ct)
    {
        if (File.Exists(VpnPlan.ServerKeyFile) && (await File.ReadAllTextAsync(VpnPlan.ServerKeyFile, ct)).Trim() is { } kept && VpnPlan.IsKey(kept)) return kept;
        Directory.CreateDirectory(VpnPlan.KeyDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var (privateKey, _) = await NewVpnKeysAsync(ct);
        await WriteSecretAsync(VpnPlan.ServerKeyFile, privateKey + "\n", ct);
        return privateKey;
    }

    public async Task<string> GetVpnServerKeyAsync(CancellationToken ct) => await PublicKeyAsync(await ServerPrivateKeyAsync(ct), ct);

    /// <summary>Written so that nobody but root can read it at any moment, even half-way: created 0600, then moved in.</summary>
    private static async Task WriteSecretAsync(string path, string content, CancellationToken ct)
    {
        var temp = path + ".palisade-tmp";
        var options = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, UnixCreateMode = RootOnly };
        await using (var file = new FileStream(temp, options))
        await using (var writer = new StreamWriter(file))
            await writer.WriteAsync(content.AsMemory(), ct);
        File.SetUnixFileMode(temp, RootOnly);
        File.Move(temp, path, overwrite: true);
    }

    /// <summary>Makes the tunnel match the config: there with its devices when the VPN is on, gone when it is off.</summary>
    private async Task ApplyTunnelAsync(FirewallConfig config, string peers, CancellationToken ct)
    {
        var exists = (await RunAsync("ip", ["link", "show", VpnPlan.Interface], ct)).ExitCode == 0;
        if (peers.Length == 0)
        {
            if (exists) await RunAsync("ip", ["link", "del", VpnPlan.Interface], ct);
            return;
        }
        if (!exists) await MustRunAsync("ip", ["link", "add", VpnPlan.Interface, "type", "wireguard"], ct);
        await SyncPeersAsync(peers, ct);
        var address = $"{config.Vpn.Address}/{config.Vpn.Prefix}";
        var current = await RunAsync("ip", ["-4", "-o", "addr", "show", "dev", VpnPlan.Interface], ct);
        if (!current.Output.Contains($" {address} ", StringComparison.Ordinal))
        {
            await RunAsync("ip", ["-4", "addr", "flush", "dev", VpnPlan.Interface], ct);
            await MustRunAsync("ip", ["addr", "add", address, "dev", VpnPlan.Interface], ct);
        }
        await MustRunAsync("ip", ["link", "set", VpnPlan.Interface, "up"], ct);
    }

    /// <summary>
    /// Hands WireGuard the device list with the firewall's key added, through a root-only file deleted straight after.
    /// "syncconf" changes only what differs, so devices already connected stay connected.
    /// </summary>
    private async Task SyncPeersAsync(string peers, CancellationToken ct)
    {
        var privateKey = await ServerPrivateKeyAsync(ct);
        var full = peers.Replace("[Interface]\n", $"[Interface]\nPrivateKey = {privateKey}\n", StringComparison.Ordinal);
        var path = Path.Combine(VpnPlan.KeyDirectory, VpnPlan.Interface + ".conf");
        await WriteSecretAsync(path, full, ct);
        try { await MustRunAsync("wg", ["syncconf", VpnPlan.Interface, path], ct); }
        finally { File.Delete(path); }
    }

    public async Task SetVpnPeersAsync(FirewallConfig live, CancellationToken ct)
    {
        _live = live.Clone();
        if (!live.Vpn.Enabled) return;
        await SyncPeersAsync(VpnPlan.PeersText(live.Vpn), ct);
        // Who may go home is in the rules: change that list at once, and in the file loaded at boot.
        var script = Path.Combine(dataDirectory, "vpn.nft");
        await File.WriteAllTextAsync(script, VpnPlan.InternetOnlyScript(live.Vpn), ct);
        await MustRunAsync("nft", ["-f", script], ct);
        await WriteAtomicAsync(NftablesConf, ConfigRenderer.Nftables(live), ct);
    }

    public async Task<VpnStatus> GetVpnStatusAsync(FirewallConfig live, CancellationToken ct)
    {
        var status = new VpnStatus { Reachability = _reach, DuckDnsHasToken = ReadDuckToken() is { Length: > 0 }, DuckDnsResult = _duckResult };
        if (!live.Vpn.Enabled) return status;
        var dump = await RunAsync("wg", ["show", VpnPlan.Interface, "dump"], ct);
        if (dump.ExitCode == 0)
            status.Peers = VpnPlan.ParseDump(dump.Output, live.Vpn,
                from => Ip4.TryParse(from, out var ip) && Ip4.TryParse(live.LanAddress, out var lan) && ip.IsIn(lan, live.LanPrefix));
        return status;
    }

    public async Task SetDuckDnsTokenAsync(string? token, CancellationToken ct)
    {
        if (token is null) return;
        if (token.Length == 0) { File.Delete(DuckDnsFile); _duckResult = ""; return; }
        await WriteSecretAsync(DuckDnsFile, JsonSerializer.Serialize(new Dictionary<string, string> { ["token"] = token }), ct);
        (_duckAt, _duckAddress) = (default, "");   // update at the next look
    }

    private string? ReadDuckToken()
    {
        try
        {
            return File.Exists(DuckDnsFile)
                ? JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(DuckDnsFile))?.GetValueOrDefault("token")
                : null;
        }
        catch (Exception ex) when (ex is JsonException or IOException) { return null; }
    }

    /// <summary>Keeps the DuckDNS name pointing at this line: when the address changes, and once an hour regardless. From the usage loop.</summary>
    private async Task UpdateDuckDnsAsync(CancellationToken ct)
    {
        if (_live is not { Vpn: { Enabled: true, DuckDnsName.Length: > 0 } vpn } live || ReadDuckToken() is not { Length: > 0 } token) return;
        var address = WanAddress(live.WanInterface);
        if (address == _duckAddress && DateTimeOffset.UtcNow < _duckAt) return;
        // Remembered before asking, so a failure waits its turn instead of being retried every 15 seconds.
        _duckAddress = address;
        _duckAt = DateTimeOffset.UtcNow + TimeSpan.FromHours(1);
        try
        {
            // The address is left blank on purpose: DuckDNS takes the one the request comes from, which is the line itself.
            var answer = (await Outside.GetStringAsync(VpnPlan.DuckDnsUpdateUrl(vpn.DuckDnsName, token), ct)).Trim();
            _duckResult = answer.StartsWith("OK", StringComparison.Ordinal)
                ? $"{vpn.DuckDnsName}{VpnPlan.DuckDnsSuffix} was last pointed at {address} on {DateTimeOffset.Now:d MMM 'at' HH:mm}."
                : "DuckDNS refused the update. Check the name and the token on duckdns.org.";
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            // Never the request itself: it carries the token.
            _duckResult = "DuckDNS could not be reached. Palisade tries again in a few minutes.";
            _duckAt = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(5);
            logger.LogInformation("Updating DuckDNS failed: {Kind}", ex.GetType().Name);
        }
    }

    private async Task<(int ExitCode, string Output, string Error)> RunWithInputAsync(string file, string[] args, string input, CancellationToken ct)
    {
        var info = new ProcessStartInfo(file) { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var arg in args) info.ArgumentList.Add(arg);
        info.Environment["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin";
        try
        {
            using var process = Process.Start(info)!;
            await process.StandardInput.WriteAsync(input.AsMemory(), ct);
            process.StandardInput.Close();
            var output = process.StandardOutput.ReadToEndAsync(ct);
            var error = process.StandardError.ReadToEndAsync(ct);
            await process.WaitForExitAsync(ct);
            return (process.ExitCode, await output, await error);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return (127, "", $"{file} is not installed");
        }
    }
}
