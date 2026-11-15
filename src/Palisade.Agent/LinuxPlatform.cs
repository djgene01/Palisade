using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Palisade.Core;

namespace Palisade.Agent;

/// <summary>Applies generated files to a Debian system. Runs as root; nothing else in the product does.</summary>
[System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
public sealed class LinuxPlatform(string dataDirectory, ILogger<LinuxPlatform> logger) : ISystemPlatform
{
    private const string NftablesConf = "/etc/nftables.conf";
    private const string DnsmasqConf = "/etc/dnsmasq.d/palisade.conf";
    private const string LanInterfaceConf = "/etc/network/interfaces.d/palisade-lan";
    private const string SysctlConf = "/etc/sysctl.d/90-palisade.conf";
    private const string LeaseFile = "/var/lib/misc/dnsmasq.leases";
    private const string DnsInstanceDirectory = "/etc/palisade/dns";

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
        await MustRunAsync("sysctl", ["-w", "net.ipv4.ip_forward=1"], ct);

        await WriteAtomicAsync(LanInterfaceConf, files.LanInterface, ct);
        var wanted = $"{config.LanAddress}/{config.LanPrefix}";
        await MustRunAsync("ip", ["link", "set", "dev", config.LanInterface, "up"], ct);
        var current = await RunAsync("ip", ["-4", "-o", "addr", "show", "dev", config.LanInterface, "scope", "global"], ct);
        var lines = current.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length != 1 || !lines[0].Contains($" {wanted} "))
        {
            await MustRunAsync("ip", ["-4", "addr", "flush", "dev", config.LanInterface, "scope", "global"], ct);
            await MustRunAsync("ip", ["addr", "add", wanted, "dev", config.LanInterface], ct);
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

        // The browser's reachability check cannot notice dead name lookups, and to a household those look
        // like "the internet is down". Failing here makes the engine put the previous settings back.
        foreach (var port in files.DnsInstances.Select(i => i.Port).Prepend(53))
            if (!await DnsProbe.AnswersAsync(config.LanAddress, port, FilterPlan.CheckName, TimeSpan.FromSeconds(8), ct))
                throw new InvalidOperationException($"the name server on port {port} did not answer after the change");
    }

    public async Task ClearAsync(CancellationToken ct)
    {
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
            status.Interfaces.Add(new InterfaceStatus(nic.Name, mac, nic.OperationalStatus == OperationalStatus.Up, addresses, stats.BytesReceived, stats.BytesSent));
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
