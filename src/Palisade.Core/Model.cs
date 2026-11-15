using System.Text.Json;
using System.Text.Json.Serialization;

namespace Palisade.Core;

public enum Protocol { Any, Tcp, Udp, TcpUdp, Icmp }
public enum RuleAction { Block, Allow }
public enum RuleDirection { Outgoing, Incoming }

public static class PalisadeDefaults
{
    public const int WebPort = 8080;
    /// <summary>Second listener used only to prove a brand-new connection still gets through after a change.</summary>
    public const int CheckPort = 8081;
    public const int SshPort = 22;
    public const int ConfirmSeconds = 60;
}

public sealed class FirewallConfig
{
    public bool SetupComplete { get; set; }
    public string WanInterface { get; set; } = "";
    public string LanInterface { get; set; } = "";
    public string LanAddress { get; set; } = "192.168.50.1";
    public int LanPrefix { get; set; } = 24;
    public bool NatEnabled { get; set; } = true;
    public bool AllowManagementFromWan { get; set; }
    public DhcpSettings Dhcp { get; set; } = new();
    public List<PortForward> PortForwards { get; set; } = [];
    public List<FirewallRule> Rules { get; set; } = [];
    public ContentFilter Filter { get; set; } = new();

    public FirewallConfig Clone() =>
        JsonSerializer.Deserialize<FirewallConfig>(JsonSerializer.Serialize(this, PalisadeJson.Options), PalisadeJson.Options)!;
}

public sealed class DhcpSettings
{
    public bool Enabled { get; set; } = true;
    public string RangeStart { get; set; } = "192.168.50.100";
    public string RangeEnd { get; set; } = "192.168.50.200";
    public int LeaseHours { get; set; } = 12;
    public List<string> UpstreamDns { get; set; } = ["1.1.1.1", "9.9.9.9"];
    public List<Reservation> Reservations { get; set; } = [];
}

public sealed class Reservation
{
    public string Id { get; set; } = NewId.Create();
    public string Name { get; set; } = "";
    public string Mac { get; set; } = "";
    public string Address { get; set; } = "";
}

public sealed class PortForward
{
    public string Id { get; set; } = NewId.Create();
    public string Name { get; set; } = "";
    public Protocol Protocol { get; set; } = Protocol.Tcp;
    /// <summary>A single port ("443") or a range ("8000-8010") on the internet side.</summary>
    public string ExternalPort { get; set; } = "";
    public string InternalAddress { get; set; } = "";
    /// <summary>Null keeps the same port number(s) as the internet side.</summary>
    public int? InternalPort { get; set; }
    public bool Enabled { get; set; } = true;
}

public sealed class FirewallRule
{
    public string Id { get; set; } = NewId.Create();
    public string Name { get; set; } = "";
    public RuleAction Action { get; set; } = RuleAction.Block;
    public RuleDirection Direction { get; set; } = RuleDirection.Outgoing;
    /// <summary>Empty means anything. Otherwise an IPv4 address or CIDR range.</summary>
    public string Source { get; set; } = "";
    public string Destination { get; set; } = "";
    public Protocol Protocol { get; set; } = Protocol.Any;
    /// <summary>Empty means every port. Otherwise "80,443,8000-8010".</summary>
    public string Ports { get; set; } = "";
    public bool Enabled { get; set; } = true;
}

public sealed record InterfaceStatus(string Name, string Mac, bool IsUp, List<string> Addresses, long RxBytes, long TxBytes);

public sealed class SystemStatus
{
    public string Hostname { get; set; } = "";
    public long UptimeSeconds { get; set; }
    public bool Simulated { get; set; }
    public List<InterfaceStatus> Interfaces { get; set; } = [];
    public bool FirewallActive { get; set; }
    public bool DhcpRunning { get; set; }
    public bool InternetReachable { get; set; }
    /// <summary>Set while a change is waiting to be confirmed; it is undone when this reaches zero.</summary>
    public int? PendingSecondsLeft { get; set; }
}

public sealed record DhcpLease(DateTimeOffset Expires, string Mac, string Address, string? Hostname);

public sealed record ValidationIssue(string Field, string Message);

public sealed class ApplyResult
{
    public bool Ok { get; set; }
    public List<ValidationIssue> Issues { get; set; } = [];
    public int ConfirmWithinSeconds { get; set; }

    public static ApplyResult Failed(IEnumerable<ValidationIssue> issues) => new() { Issues = [.. issues] };
    public static ApplyResult Failed(string message) => new() { Issues = [new("", message)] };
}

public interface IFirewallBackend
{
    Task<SystemStatus> GetStatusAsync(CancellationToken ct = default);
    Task<FirewallConfig> GetConfigAsync(CancellationToken ct = default);
    Task<ApplyResult> ApplyAsync(FirewallConfig config, CancellationToken ct = default);
    Task ConfirmAsync(CancellationToken ct = default);
    Task RevertAsync(CancellationToken ct = default);
    Task<IReadOnlyList<DhcpLease>> GetLeasesAsync(CancellationToken ct = default);
}

public static class NewId
{
    public static string Create() => Guid.NewGuid().ToString("N")[..10];
}

public static class PalisadeJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };
}
