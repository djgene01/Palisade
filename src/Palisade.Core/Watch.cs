using System.Globalization;
using System.Text.Json;

namespace Palisade.Core;

/// <summary>One place on the other side that a watched device talked to, and how much went each way.</summary>
public sealed record WatchFlow(string Address, string Protocol, int Port, long DownBytes, long UpBytes)
{
    /// <summary>The name the internet gives for the address, when it has one. Empty otherwise.</summary>
    public string Name { get; init; } = "";
}

public sealed class WatchRequest
{
    public string Address { get; set; } = "";
    public int Seconds { get; set; } = WatchPlan.DefaultSeconds;
}

public sealed class WatchReport
{
    public string Address { get; set; } = "";
    public int Seconds { get; set; }
    public List<WatchFlow> Flows { get; set; } = [];
    /// <summary>Why the watch could not run, in plain words. Empty when it did.</summary>
    public string Problem { get; set; } = "";
}

public interface ITrafficWatch
{
    /// <summary>Counts, for a short while, who one device talks to. Only addresses, ports and sizes are counted: nothing that is said is read or kept.</summary>
    Task<WatchReport> WatchAsync(WatchRequest request, CancellationToken ct = default);
}

public static class WatchPlan
{
    public const string Table = "palisade_watch";
    public const string UpSet = "sent";
    public const string DownSet = "received";
    public const int DefaultSeconds = 20;
    public const int MaxSeconds = 45;

    public static int Seconds(int asked) => Math.Clamp(asked, 5, MaxSeconds);

    /// <summary>
    /// A table of its own that sits beside the firewall rules and decides nothing. It counts every packet
    /// the device sends or receives through the firewall, grouped by the far address and port, and is
    /// removed again when the watch ends.
    /// </summary>
    public static string Script(string address)
    {
        if (!Ip4.TryParse(address, out var ip) || ip.ToString() != address) throw new InvalidOperationException($"Unsafe address: {address}");
        const string kind = "type ipv4_addr . inet_proto . inet_service; size 8192; flags dynamic; counter;";
        return $$"""
            table inet {{Table}}
            delete table inet {{Table}}
            table inet {{Table}} {
                set {{UpSet}} { {{kind}} }
                set {{DownSet}} { {{kind}} }
                chain watch {
                    type filter hook forward priority -9; policy accept;
                    ip saddr {{ip}} meta l4proto { tcp, udp } update @{{UpSet}} { ip daddr . meta l4proto . th dport }
                    ip daddr {{ip}} meta l4proto { tcp, udp } update @{{DownSet}} { ip saddr . meta l4proto . th sport }
                }
            }

            """.Replace("\r\n", "\n");
    }

    /// <summary>Reads one counted set from "nft -j list set": far address, protocol and port to bytes.</summary>
    public static Dictionary<(string Address, string Protocol, int Port), long> ParseFlows(string json)
    {
        var result = new Dictionary<(string, string, int), long>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("nftables", out var items)) return result;
            foreach (var item in items.EnumerateArray())
            {
                if (!item.TryGetProperty("set", out var set) || !set.TryGetProperty("elem", out var elems)) continue;
                foreach (var wrapped in elems.EnumerateArray())
                {
                    if (wrapped.ValueKind != JsonValueKind.Object || !wrapped.TryGetProperty("elem", out var elem)) continue;
                    if (!elem.TryGetProperty("val", out var val) || val.ValueKind != JsonValueKind.Object) continue;
                    if (!val.TryGetProperty("concat", out var parts) || parts.GetArrayLength() != 3) continue;
                    if (parts[0].ValueKind != JsonValueKind.String || !Ip4.TryParse(parts[0].GetString(), out var ip)) continue;
                    var protocol = parts[1].ValueKind == JsonValueKind.Number
                        ? parts[1].GetInt32() switch { 6 => "tcp", 17 => "udp", _ => "" }
                        : parts[1].GetString() is "tcp" or "udp" ? parts[1].GetString()! : "";
                    if (protocol.Length == 0 || parts[2].ValueKind != JsonValueKind.Number || !parts[2].TryGetInt32(out var port) || port is < 0 or > 65535) continue;
                    if (elem.TryGetProperty("counter", out var counter) && counter.TryGetProperty("bytes", out var bytes) && bytes.TryGetInt64(out var count))
                        result[(ip.ToString(), protocol, port)] = count;
                }
            }
        }
        catch (JsonException)
        {
        }
        return result;
    }

    /// <summary>Joins the two directions into one line per far address and port, biggest first.</summary>
    public static List<WatchFlow> Merge(Dictionary<(string Address, string Protocol, int Port), long> up, Dictionary<(string Address, string Protocol, int Port), long> down) =>
        [.. up.Keys.Union(down.Keys)
            .Select(k => new WatchFlow(k.Address, k.Protocol, k.Port, down.GetValueOrDefault(k), up.GetValueOrDefault(k)))
            .OrderByDescending(f => f.DownBytes + f.UpBytes)];

    /// <summary>What a port is normally used for, in words a person might recognise.</summary>
    public static string PortName(string protocol, int port) => (protocol, port) switch
    {
        (_, 443) => "Secure web (HTTPS)",
        ("tcp", 80) => "Web (HTTP)",
        (_, 53) => "Name lookups (DNS)",
        (_, 853) => "Encrypted name lookups",
        ("udp", 123) => "Clock (NTP)",
        ("tcp", 1883) => "Smart-home messages (MQTT)",
        ("tcp", 8883) => "Secure smart-home messages (MQTT)",
        ("tcp", 22) => "Remote login (SSH)",
        ("tcp", 25 or 465 or 587) => "Sending email",
        ("tcp", 143 or 993 or 110 or 995) => "Reading email",
        ("tcp", 554) => "Video stream (RTSP)",
        ("tcp", 1935) => "Video stream (RTMP)",
        ("udp", 3478 or 3479 or 5349) => "Calls and video (STUN)",
        ("udp", 500 or 4500 or 1194 or 51820) => "VPN",
        ("tcp", 6667 or 6697) => "Chat (IRC)",
        ("tcp", 23) => "Telnet",
        ("tcp", 8080 or 8443) => "Web, on another port",
        _ => $"{protocol.ToUpperInvariant()} port {port.ToString(CultureInfo.InvariantCulture)}",
    };
}
