using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Palisade.Core;

namespace Palisade.Agent;

/// <summary>Applies generated files to a Debian system. Runs as root; nothing else in the product does.</summary>
[System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
public sealed class LinuxPlatform(string dataDirectory, ILogger<LinuxPlatform> logger) : ISystemPlatform, ITrafficWatch
{
    private readonly SemaphoreSlim _watchGate = new(1, 1);

    public async Task<WatchReport> WatchAsync(WatchRequest request, CancellationToken ct = default)
    {
        var seconds = WatchPlan.Seconds(request.Seconds);
        var report = new WatchReport { Address = request.Address, Seconds = seconds };
        if (!Ip4.TryParse(request.Address, out var ip) || ip.ToString() != request.Address)
        {
            report.Problem = "That is not a device address.";
            return report;
        }
        // One watch at a time: they share one counting table.
        if (!await _watchGate.WaitAsync(0, ct))
        {
            report.Problem = "Another device is being watched right now. Try again in a moment.";
            return report;
        }
        try
        {
            var script = Path.Combine(dataDirectory, "watch.nft");
            await File.WriteAllTextAsync(script, WatchPlan.Script(request.Address), ct);
            var started = await RunAsync("nft", ["-f", script], ct);
            if (started.ExitCode != 0)
            {
                report.Problem = $"The firewall could not start counting. ({started.Error.Trim()})";
                return report;
            }
            await Task.Delay(TimeSpan.FromSeconds(seconds), ct);
            var sent = await RunAsync("nft", ["-j", "list", "set", "inet", WatchPlan.Table, WatchPlan.UpSet], ct);
            var received = await RunAsync("nft", ["-j", "list", "set", "inet", WatchPlan.Table, WatchPlan.DownSet], ct);
            if (sent.ExitCode != 0 || received.ExitCode != 0)
            {
                // Saving a setting reloads every rule, which also clears this table.
                report.Problem = "The count was interrupted, most likely by a setting being saved. Try again.";
                return report;
            }
            var flows = WatchPlan.Merge(WatchPlan.ParseFlows(sent.Output), WatchPlan.ParseFlows(received.Output));
            report.Flows = [.. await Task.WhenAll(flows.Take(40).Select(async f => f with { Name = await NameOfAsync(f.Address) }))];
            return report;
        }
        finally
        {
            await RunAsync("nft", ["delete", "table", "inet", WatchPlan.Table], CancellationToken.None);
            _watchGate.Release();
        }
    }

    /// <summary>Asks the internet what an address calls itself. Many have no name, and a slow answer is not worth waiting for.</summary>
    private static async Task<string> NameOfAsync(string address)
    {
        try
        {
            var name = (await System.Net.Dns.GetHostEntryAsync(address).WaitAsync(TimeSpan.FromSeconds(3))).HostName.TrimEnd('.').ToLowerInvariant();
            return SiteName.IsValid(name) ? name : "";
        }
        catch (Exception) { return ""; }
    }

    private const string NftablesConf = "/etc/nftables.conf";
    private const string DnsmasqConf = "/etc/dnsmasq.d/palisade.conf";
    private const string LanInterfaceConf = "/etc/network/interfaces.d/palisade-lan";
    private const string SysctlConf = "/etc/sysctl.d/90-palisade.conf";
    private const string LeaseFile = "/var/lib/misc/dnsmasq.leases";
    private const string DnsInstanceDirectory = "/etc/palisade/dns";
    private const string InterfacesFile = "/etc/network/interfaces";
    private const string WanInterfaceConf = "/etc/network/interfaces.d/palisade-wan";
    private const string WifiInterfaceConf = "/etc/network/interfaces.d/palisade-wifi";

    private readonly SemaphoreSlim _wifiGate = new(1, 1);

    private readonly UsageTracker _usage = new(DateTimeOffset.UtcNow);
    private readonly SemaphoreSlim _accessGate = new(1, 1);
    private IReadOnlyList<DeviceAccess> _access = [];
    private string? _pausedInKernel;
    private readonly SemaphoreSlim _usageGate = new(1, 1);
    private DateTimeOffset _internetCheckedAt;
    private bool _internetReachable;

    public async Task<IReadOnlyList<string>> CheckAsync(FirewallConfig config, GeneratedFiles files, CancellationToken ct)
    {
        var problems = new List<string>();

        // Applying replaces every address on the home network port. If that port is the one this machine
        // reaches the internet through, doing so would cut the machine off in a way undo cannot repair.
        var uplink = await RunAsync("ip", ["-4", "route", "show", "default", "dev", config.LanInterface], ct);
        if (uplink.ExitCode == 0 && uplink.Output.Trim().Length > 0)
        {
            problems.Add($"Port {config.LanInterface} is the one this machine uses to reach the internet, so it can't be the home network port. Choose the other port for your devices.");
            return problems;
        }
        // The same range on both sides is the one mistake that makes the whole firewall unreachable:
        // replies meant for the internet side leave through the home network port instead.
        if (Ip4.TryParse(config.LanAddress, out var lan))
        {
            var wan = await RunAsync("ip", ["-4", "-o", "addr", "show", "dev", config.WanInterface, "scope", "global"], ct);
            foreach (var word in wan.Output.Split([' ', '\n'], StringSplitOptions.RemoveEmptyEntries))
            {
                if (!word.Contains('/') || !AddressSpec.TryParseCidr(word, out var address, out var prefix)) continue;
                if (lan.IsIn(address, Math.Min(prefix, config.LanPrefix)))
                {
                    problems.Add($"The internet port ({config.WanInterface}) has the address {word}, which is in the same range as your network ({config.LanAddress}). Give your network a different range, such as 192.168.50.1 or 10.10.10.1.");
                    return problems;
                }
                foreach (var extra in config.ExtraNetworks)
                {
                    if (!Ip4.TryParse(extra.Address, out var own) || !own.IsIn(address, Math.Min(prefix, extra.Prefix))) continue;
                    problems.Add($"The internet port ({config.WanInterface}) has the address {word}, which is in the same range as the extra network \"{extra.Name}\". That range is already reachable through the internet port, so remove the extra network.");
                    return problems;
                }
            }
        }

        var nft = Path.Combine(dataDirectory, "candidate.nft");
        var dnsmasq = Path.Combine(dataDirectory, "candidate.dnsmasq.conf");
        await File.WriteAllTextAsync(nft, files.Nftables, ct);
        await File.WriteAllTextAsync(dnsmasq, files.Dnsmasq, ct);

        var nftCheck = await RunAsync("nft", ["-c", "-f", nft], ct);
        if (nftCheck.ExitCode != 0) problems.Add($"The firewall rules were rejected: {nftCheck.Error.Trim()}");
        var dnsmasqCheck = await RunAsync("dnsmasq", ["--test", $"--conf-file={dnsmasq}"], ct);
        if (dnsmasqCheck.ExitCode != 0) problems.Add($"The DHCP settings were rejected: {dnsmasqCheck.Error.Trim()}");
        foreach (var instance in files.DnsInstances)
        {
            var path = Path.Combine(dataDirectory, $"candidate.dns-{instance.Name}.conf");
            await File.WriteAllTextAsync(path, instance.Conf, ct);
            var check = await RunAsync("dnsmasq", ["--test", $"--conf-file={path}"], ct);
            if (check.ExitCode != 0) problems.Add($"The content filter settings were rejected: {check.Error.Trim()}");
        }
        return problems;
    }

    public async Task ApplyAsync(FirewallConfig config, GeneratedFiles files, CancellationToken ct)
    {
        await WriteAtomicAsync(SysctlConf, files.Sysctl, ct);
        await MustRunAsync("sysctl", ["-q", "-p", SysctlConf], ct);

        await ApplyWanPortAsync(config.WanInterface, files.WanInterface, ct);
        await WriteAtomicAsync(LanInterfaceConf, files.LanInterface, ct);
        var wanted = ConfigRenderer.LanAddresses(config);
        await MustRunAsync("ip", ["link", "set", "dev", config.LanInterface, "up"], ct);
        var current = await RunAsync("ip", ["-4", "-o", "addr", "show", "dev", config.LanInterface, "scope", "global"], ct);
        var lines = current.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length != wanted.Count || wanted.Any(w => !lines.Any(l => l.Contains($" {w} "))))
        {
            await MustRunAsync("ip", ["-4", "addr", "flush", "dev", config.LanInterface, "scope", "global"], ct);
            foreach (var address in wanted)
                await MustRunAsync("ip", ["addr", "add", address, "dev", config.LanInterface], ct);
        }

        // The name servers start before the rules that point devices at them, so no lookup is sent to a port nobody answers yet.
        await WriteAtomicAsync(DnsmasqConf, files.Dnsmasq, ct);
        await MustRunAsync("systemctl", ["enable", "dnsmasq"], ct);
        await MustRunAsync("systemctl", ["restart", "dnsmasq"], ct);
        foreach (var level in FilterPlan.AllLevels)
        {
            var unit = InstanceUnit(level);
            if (files.DnsInstances.FirstOrDefault(i => i.Level == level) is { } instance)
            {
                await WriteAtomicAsync(InstanceConf(level), instance.Conf, ct);
                await MustRunAsync("systemctl", ["enable", unit], ct);
                await MustRunAsync("systemctl", ["restart", unit], ct);
            }
            else await StopInstanceAsync(level, ct);
        }

        // nftables.service loads this same file at boot, so protection never depends on this agent being up.
        await WriteAtomicAsync(NftablesConf, files.Nftables, ct);
        await MustRunAsync("nft", ["-f", NftablesConf], ct);
        // Loading the rules emptied the set of paused devices, so fill it again straight away.
        await SetAccessAsync(config.Access, forget: true, ct);

        // The browser's reachability check cannot notice dead name lookups, and to a household those look
        // like "the internet is down". Failing here makes the engine put the previous settings back.
        foreach (var port in files.DnsInstances.Select(i => i.Port).Prepend(53))
            if (!await DnsProbe.AnswersAsync(config.LanAddress, port, FilterPlan.CheckName, TimeSpan.FromSeconds(8), ct))
                throw new InvalidOperationException($"the name server on port {port} did not answer after the change");
    }

    public Task SetAccessAsync(IReadOnlyList<DeviceAccess> access, CancellationToken ct) => SetAccessAsync(access, forget: false, ct);

    private async Task SetAccessAsync(IReadOnlyList<DeviceAccess>? access, bool forget, CancellationToken ct)
    {
        await _accessGate.WaitAsync(ct);
        try
        {
            if (access is not null) _access = access;
            if (forget) _pausedInKernel = null;
            var script = AccessPlan.SetScript(AccessPlan.OffNow(_access, DateTimeOffset.UtcNow, DateTime.Now));
            // The clock is checked often, but the kernel is only touched when the answer changed.
            if (script == _pausedInKernel) return;
            var path = Path.Combine(dataDirectory, "paused.nft");
            await File.WriteAllTextAsync(path, script, ct);
            var result = await RunAsync("nft", ["-f", path], ct);
            if (result.ExitCode == 0) _pausedInKernel = script;
            // Before first setup there is no table to fill, which is not worth a warning.
            else if (_access.Count > 0) logger.LogWarning("Could not update the paused devices: {Error}", result.Error.Trim());
        }
        finally { _accessGate.Release(); }
    }

    /// <summary>Starts and ends off times and timed pauses as the clock moves. Started once by the host.</summary>
    public async Task WatchClockAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(10));
        try
        {
            while (await timer.WaitForNextTickAsync(ct))
            {
                try { await SetAccessAsync(null, forget: false, ct); }
                catch (Exception ex) when (ex is not OperationCanceledException) { logger.LogWarning(ex, "Checking the off times failed"); }
            }
        }
        catch (OperationCanceledException) { }
    }

    public async Task ClearAsync(CancellationToken ct)
    {
        await _accessGate.WaitAsync(ct);
        _pausedInKernel = null;
        _accessGate.Release();
        await WriteAtomicAsync(NftablesConf, "#!/usr/sbin/nft -f\nflush ruleset\n", ct);
        await RunAsync("nft", ["flush", "ruleset"], ct);
        File.Delete(DnsmasqConf);
        await RunAsync("systemctl", ["disable", "--now", "dnsmasq"], ct);
        foreach (var level in FilterPlan.AllLevels) await StopInstanceAsync(level, ct);
    }

    private static string InstanceUnit(FilterLevel level) => $"palisade-dns@{FilterPlan.Name(level)}.service";

    private static string InstanceConf(FilterLevel level) => $"{DnsInstanceDirectory}/{FilterPlan.Name(level)}.conf";

    private async Task StopInstanceAsync(FilterLevel level, CancellationToken ct)
    {
        if (!File.Exists(InstanceConf(level))) return;
        await RunAsync("systemctl", ["disable", "--now", InstanceUnit(level)], ct);
        File.Delete(InstanceConf(level));
    }

    public async Task<SystemStatus> GetStatusAsync(FirewallConfig active, CancellationToken ct)
    {
        var status = new SystemStatus
        {
            Hostname = Environment.MachineName,
            UptimeSeconds = Environment.TickCount64 / 1000,
        };

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            var addresses = nic.GetIPProperties().UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => $"{a.Address}/{a.PrefixLength}")
                .ToList();
            var stats = nic.GetIPStatistics();
            var mac = string.Join(':', nic.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("x2")));
            status.Interfaces.Add(new InterfaceStatus(nic.Name, mac, nic.OperationalStatus == OperationalStatus.Up, addresses, stats.BytesReceived, stats.BytesSent) { IsWireless = IsWireless(nic.Name) });
        }

        status.FirewallActive = (await RunAsync("nft", ["list", "table", "inet", "palisade"], ct)).ExitCode == 0;
        status.DhcpRunning = (await RunAsync("systemctl", ["is-active", "--quiet", "dnsmasq"], ct)).ExitCode == 0;
        status.InternetReachable = await CheckInternetAsync(active, ct);
        return status;
    }

    public async Task<IReadOnlyList<DhcpLease>> GetLeasesAsync(CancellationToken ct)
    {
        if (!File.Exists(LeaseFile)) return [];
        var now = DateTimeOffset.UtcNow;
        return LeaseParser.Parse(await File.ReadAllTextAsync(LeaseFile, ct)).Where(l => l.Expires > now).ToList();
    }

    /// <summary>Keeps the totals growing while nobody has the overview open. Started once by the host.</summary>
    public async Task WatchUsageAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        try
        {
            do { await GetUsageAsync(ct); }
            while (await timer.WaitForNextTickAsync(ct));
        }
        catch (OperationCanceledException) { }
    }

    public async Task<UsageReport> GetUsageAsync(CancellationToken ct)
    {
        await _usageGate.WaitAsync(ct);
        try
        {
            var now = DateTimeOffset.UtcNow;
            // The overview asks every two seconds, possibly from several browsers. Reading more often than
            // that gains nothing and would make the speeds jumpy.
            if (now - _usage.LastSampleAt >= TimeSpan.FromSeconds(1.5))
            {
                var received = await RunAsync("nft", ["-j", "list", "set", "inet", ConfigRenderer.UsageTable, ConfigRenderer.UsageDownSet], ct);
                var sent = await RunAsync("nft", ["-j", "list", "set", "inet", ConfigRenderer.UsageTable, ConfigRenderer.UsageUpSet], ct);
                // Before first setup the table does not exist yet; an empty reading is the truth then.
                var down = received.ExitCode == 0 ? UsageParser.ParseSet(received.Output) : [];
                var up = sent.ExitCode == 0 ? UsageParser.ParseSet(sent.Output) : [];
                _usage.Record(now, down.Keys.Union(up.Keys).ToDictionary(a => a, a => (down.GetValueOrDefault(a), up.GetValueOrDefault(a))));
            }
            return _usage.Report(now);
        }
        finally { _usageGate.Release(); }
    }

    private static bool IsWireless(string name) => Directory.Exists($"/sys/class/net/{name}/wireless");

    private static string ReadOrEmpty(string path) => File.Exists(path) ? File.ReadAllText(path) : "";

    /// <summary>
    /// A wired internet port needs something to ask the provider for an address. Debian only sets that up
    /// for the port chosen during its own installation, so Palisade does it for any other wired port.
    /// </summary>
    private async Task ApplyWanPortAsync(string wan, string stanza, CancellationToken ct)
    {
        var before = ReadOrEmpty(WanInterfaceConf);
        var wanted = IsWireless(wan) || WifiPlan.IsDefined(ReadOrEmpty(InterfacesFile), wan) || WifiPlan.IsDefined(ReadOrEmpty(WifiInterfaceConf), wan) ? "" : stanza;
        if (before == wanted) return;

        // Release the port Palisade looked after until now, while its description is still on disk.
        var previous = System.Text.RegularExpressions.Regex.Match(before, @"^iface (\S+) ", System.Text.RegularExpressions.RegexOptions.Multiline);
        if (previous.Success && previous.Groups[1].Value != wan) await RunAsync("ifdown", ["--force", previous.Groups[1].Value], ct);

        if (wanted.Length == 0)
        {
            File.Delete(WanInterfaceConf);
            return;
        }
        await WriteAtomicAsync(WanInterfaceConf, wanted, ct);
        // Asking for an address can take half a minute with no cable in, far longer than a save may take,
        // so it carries on by itself. Plugging the cable in later starts it again.
        _ = Task.Run(async () =>
        {
            var up = await RunAsync("ifup", [wan], CancellationToken.None);
            if (up.ExitCode != 0) logger.LogWarning("Bringing up the internet port {Port} did not succeed: {Error}", wan, up.Error.Trim());
        }, CancellationToken.None);
    }

    private static string? WifiInterface() =>
        NetworkInterface.GetAllNetworkInterfaces().Select(n => n.Name).FirstOrDefault(IsWireless);

    public async Task<WifiStatus> GetWifiAsync(CancellationToken ct)
    {
        if (WifiInterface() is not { } iface) return new WifiStatus();
        var status = new WifiStatus { Interface = iface };
        var cli = await RunAsync("wpa_cli", ["-i", iface, "status"], ct);
        foreach (var line in cli.Output.Split('\n', StringSplitOptions.TrimEntries))
        {
            if (line.StartsWith("ssid=", StringComparison.Ordinal)) status.Ssid = line[5..];
            else if (line == "wpa_state=COMPLETED") status.Connected = true;
            else if (line.StartsWith("ip_address=", StringComparison.Ordinal)) status.Address = line[11..];
        }
        return status;
    }

    public async Task<ApplyResult> SetWifiAsync(WifiRequest request, CancellationToken requestAborted)
    {
        if (WifiInterface() is not { } iface) return ApplyResult.Failed("This machine has no Wi-Fi.");
        // Whoever asked may be connected through this very Wi-Fi and vanish halfway. The change, and the
        // step back if it fails, must still run to the end, so nothing below listens to the caller leaving.
        var ct = CancellationToken.None;
        await _wifiGate.WaitAsync(ct);
        try
        {
            var oldMain = ReadOrEmpty(InterfacesFile);
            var oldStanza = File.Exists(WifiInterfaceConf) ? File.ReadAllText(WifiInterfaceConf) : null;
            var oldSupplicant = File.Exists(WifiPlan.SupplicantPath) ? File.ReadAllText(WifiPlan.SupplicantPath) : null;
            if (!File.Exists(InterfacesFile + ".before-palisade") && File.Exists(InterfacesFile))
                File.Copy(InterfacesFile, InterfacesFile + ".before-palisade");

            // Taken down with the old description still on disk, so its own cleanup steps run.
            await RunAsync("ifdown", ["--force", iface], ct);
            WriteSecret(WifiPlan.SupplicantPath, WifiPlan.SupplicantConf(request));
            await WriteAtomicAsync(InterfacesFile, WifiPlan.StripStanza(oldMain, iface), ct);
            await WriteAtomicAsync(WifiInterfaceConf, WifiPlan.WifiStanza(iface), ct);
            _ = Task.Run(() => RunAsync("ifup", [iface], CancellationToken.None), CancellationToken.None);

            var deadline = DateTimeOffset.UtcNow.AddSeconds(22);
            while (DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(1000, ct);
                if ((await GetWifiAsync(ct)).Connected) return new ApplyResult { Ok = true };
            }

            logger.LogWarning("Could not join the Wi-Fi network, putting the previous Wi-Fi settings back");
            await RunAsync("ifdown", ["--force", iface], ct);
            await WriteAtomicAsync(InterfacesFile, oldMain, ct);
            if (oldStanza is null) File.Delete(WifiInterfaceConf); else await WriteAtomicAsync(WifiInterfaceConf, oldStanza, ct);
            if (oldSupplicant is null) File.Delete(WifiPlan.SupplicantPath); else WriteSecret(WifiPlan.SupplicantPath, oldSupplicant);
            _ = Task.Run(() => RunAsync("ifup", [iface], CancellationToken.None), CancellationToken.None);
            return ApplyResult.Failed("The firewall could not join that Wi-Fi network. Check the name and the password. The previous Wi-Fi settings are back in use.");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Changing the Wi-Fi failed");
            return ApplyResult.Failed($"The Wi-Fi could not be changed. ({ex.Message})");
        }
        finally { _wifiGate.Release(); }
    }

    /// <summary>Holds a key to a Wi-Fi network, so only root may read it, from the moment the file exists.</summary>
    private static void WriteSecret(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".palisade-tmp";
        File.Delete(temp);
        using (var stream = new FileStream(temp, new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite }))
            stream.Write(System.Text.Encoding.UTF8.GetBytes(content));
        File.Move(temp, path, overwrite: true);
    }

    private async Task<bool> CheckInternetAsync(FirewallConfig active, CancellationToken ct)
    {
        if (DateTimeOffset.UtcNow - _internetCheckedAt < TimeSpan.FromSeconds(20)) return _internetReachable;
        _internetCheckedAt = DateTimeOffset.UtcNow;
        var target = active.Dhcp.UpstreamDns.FirstOrDefault() ?? "1.1.1.1";
        try
        {
            using var client = new TcpClient();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            await client.ConnectAsync(target, 53, timeout.Token);
            _internetReachable = true;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            _internetReachable = false;
        }
        return _internetReachable;
    }

    private static async Task WriteAtomicAsync(string path, string content, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".palisade-tmp";
        await File.WriteAllTextAsync(temp, content, ct);
        File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        File.Move(temp, path, overwrite: true);
    }

    private async Task MustRunAsync(string file, string[] args, CancellationToken ct)
    {
        var result = await RunAsync(file, args, ct);
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"{file} {string.Join(' ', args)} failed: {result.Error.Trim()}");
    }

    // Arguments are always passed as a list, never through a shell, so config values cannot become commands.
    private async Task<(int ExitCode, string Output, string Error)> RunAsync(string file, string[] args, CancellationToken ct)
    {
        var info = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var arg in args) info.ArgumentList.Add(arg);
        info.Environment["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin";
        try
        {
            using var process = Process.Start(info)!;
            var output = process.StandardOutput.ReadToEndAsync(ct);
            var error = process.StandardError.ReadToEndAsync(ct);
            await process.WaitForExitAsync(ct);
            return (process.ExitCode, await output, await error);
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            logger.LogError(ex, "Could not start {File}", file);
            return (127, "", $"{file} is not installed");
        }
    }
}
