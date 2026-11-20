using System.Globalization;
using System.Text.Json;

namespace Palisade.Core;

/// <summary>How often the firewall tests the internet connection by itself, and whether the owner accepted Ookla's terms.</summary>
public sealed class SpeedSettings
{
    public bool Enabled { get; set; }
    public int IntervalMinutes { get; set; } = SpeedPlan.DefaultInterval;
    /// <summary>When the owner accepted Ookla's licence, terms and privacy policy. Null: no test may run.</summary>
    public DateTimeOffset? TermsAcceptedAt { get; set; }
}

public sealed class SpeedSettingsRequest
{
    public bool Enabled { get; set; }
    public int IntervalMinutes { get; set; } = SpeedPlan.DefaultInterval;
    /// <summary>The owner ticked "I accept Ookla's terms". Needed once, before the first test.</summary>
    public bool AcceptTerms { get; set; }
}

/// <summary>One speed test. Speeds in bits per second. Problem is set, and the numbers are zero, when it failed.</summary>
public sealed class SpeedResult
{
    public DateTimeOffset At { get; set; }
    /// <summary>"scheduled" or "manual".</summary>
    public string Trigger { get; set; } = SpeedPlan.Scheduled;
    public double DownloadBps { get; set; }
    public double UploadBps { get; set; }
    public double PingMs { get; set; }
    public double JitterMs { get; set; }
    /// <summary>Lost packets in percent, when the server could measure it.</summary>
    public double? PacketLoss { get; set; }
    /// <summary>The test server, such as "Active Fibre, Johannesburg".</summary>
    public string Server { get; set; } = "";
    public string Isp { get; set; } = "";
    /// <summary>The result on speedtest.net, to share.</summary>
    public string ResultUrl { get; set; } = "";
    /// <summary>What the test itself sent and received, so the owner can see what testing costs.</summary>
    public long DataBytes { get; set; }
    public string Problem { get; set; } = "";
}

public sealed class SpeedStatus
{
    public SpeedSettings Settings { get; set; } = new();
    /// <summary>True when Ookla's program is on the firewall. It is fetched on the first test.</summary>
    public bool Installed { get; set; }
    public bool Running { get; set; }
    public DateTimeOffset? NextAt { get; set; }
    /// <summary>Why the last scheduled test was put off, such as the household using the internet. Empty when it wasn't.</summary>
    public string Postponed { get; set; } = "";
    /// <summary>Newest first, for the last 31 days.</summary>
    public List<SpeedResult> History { get; set; } = [];
    /// <summary>What went wrong with the last request, in plain words, such as terms not yet accepted or a firewall too old to test. Empty when all is well.</summary>
    public string Problem { get; set; } = "";

    public SpeedResult? Last => History.FirstOrDefault();
}

/// <summary>Tests the internet connection with Speedtest by Ookla, by schedule and on request.</summary>
public interface ISpeedTest
{
    Task<SpeedStatus> GetSpeedAsync(CancellationToken ct = default);
    Task<SpeedStatus> SetSpeedAsync(SpeedSettingsRequest request, CancellationToken ct = default);
    /// <summary>Starts a test now and returns at once; <see cref="SpeedStatus.Running"/> stays true until it is done.</summary>
    Task<SpeedStatus> RunSpeedTestAsync(CancellationToken ct = default);
}

public static class SpeedPlan
{
    public const string Scheduled = "scheduled", Manual = "manual";
    public const int DefaultInterval = 30;
    public static readonly int[] Intervals = [30, 60, 180, 360];
    public static readonly TimeSpan Kept = TimeSpan.FromDays(31);
    /// <summary>A postponed test is tried again this much later, until the household is quiet.</summary>
    public static readonly TimeSpan RetryAfterBusy = TimeSpan.FromMinutes(5);

    // Ookla's own program, fetched from Ookla by the firewall when the owner first tests: it may not be shipped with
    // Palisade. Only this exact file is ever run.
    public const string CliVersion = "1.2.0";
    public const string CliUrl = "https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz";
    public const string CliSha256 = "5690596c54ff9bed63fa3732f818a05dbc2db19ad36ed68f21ca5f64d5cfeeb7";
    public const long CliSize = 1_106_829;

    public const string EulaUrl = "https://www.speedtest.net/about/eula";
    public const string TermsUrl = "https://www.speedtest.net/about/terms";
    public const string PrivacyUrl = "https://www.speedtest.net/about/privacy";

    public static string? Validate(SpeedSettingsRequest r, SpeedSettings current)
    {
        if (!Intervals.Contains(r.IntervalMinutes)) return "Choose how often to test: every 30 minutes, 1, 3 or 6 hours.";
        if (r.Enabled && current.TermsAcceptedAt is null && !r.AcceptTerms)
            return "Tests use Speedtest by Ookla. Accept Ookla's terms first.";
        return null;
    }

    /// <summary>
    /// True when the household is using the internet enough that a test would both slow them down and measure
    /// too little: more than a fifth of the last download speed, or more than 5 Mbit/s before the first test.
    /// </summary>
    public static bool IsBusy(UsageReport usage, SpeedResult? last)
    {
        var inUse = usage.Devices.Sum(d => d.DownRate + d.UpRate) * 8;
        var threshold = last is { DownloadBps: > 0 } ? Math.Max(5e6, last.DownloadBps * 0.2) : 5e6;
        return inUse > threshold;
    }

    /// <summary>How many results keep their server, ISP and link when sent to a page; older ones carry the numbers only.</summary>
    public const int DetailedResults = 20;

    /// <summary>
    /// The history as sent to a page or the app, which ask often: a month of half-hourly tests in full would be
    /// hundreds of kilobytes, so only the newest keep their words and links.
    /// </summary>
    public static List<SpeedResult> ForWire(IEnumerable<SpeedResult> history) =>
        [.. history.Select((r, i) => i < DetailedResults ? r : new SpeedResult
        {
            At = r.At, Trigger = r.Trigger, DownloadBps = Math.Round(r.DownloadBps), UploadBps = Math.Round(r.UploadBps),
            PingMs = r.PingMs, JitterMs = r.JitterMs, PacketLoss = r.PacketLoss, DataBytes = r.DataBytes, Problem = r.Problem,
        })];

    /// <summary>Reads what "speedtest -f json" printed: the result line, or the error it logged instead.</summary>
    public static SpeedResult Parse(string output, DateTimeOffset at, string trigger)
    {
        var result = new SpeedResult { At = at, Trigger = trigger };
        string? error = null;
        foreach (var line in output.Split('\n').Select(l => l.Trim()).Where(l => l.StartsWith('{')))
        {
            try
            {
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;
                var type = Text(root, "type");
                if (type == "log" && Text(root, "level") == "error") error ??= Text(root, "message");
                if (type != "result") continue;
                result.PingMs = Number(root, "ping", "latency");
                result.JitterMs = Number(root, "ping", "jitter");
                // Ookla reports bandwidth in bytes per second.
                result.DownloadBps = Number(root, "download", "bandwidth") * 8;
                result.UploadBps = Number(root, "upload", "bandwidth") * 8;
                result.DataBytes = (long)(Number(root, "download", "bytes") + Number(root, "upload", "bytes"));
                result.PacketLoss = root.TryGetProperty("packetLoss", out var loss) && loss.ValueKind == JsonValueKind.Number ? Math.Round(loss.GetDouble(), 2) : null;
                result.Isp = Short(Text(root, "isp"));
                if (root.TryGetProperty("server", out var server))
                    result.Server = Short(string.Join(", ", new[] { Text(server, "name"), Text(server, "location") }.Where(s => s.Length > 0)));
                if (root.TryGetProperty("result", out var shared) && Text(shared, "url") is { } url
                    && url.StartsWith("https://www.speedtest.net/result/", StringComparison.Ordinal) && url.Length < 200)
                    result.ResultUrl = url;
                // The public address and hardware details Ookla also returns are deliberately not kept.
                return result;
            }
            catch (JsonException) { }
        }
        result.Problem = error is { Length: > 0 } ? $"The speed test failed: {Short(error)}" : "The speed test gave no result.";
        return result;
    }

    private static string Text(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static double Number(JsonElement e, string outer, string inner) =>
        e.TryGetProperty(outer, out var o) && o.TryGetProperty(inner, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : 0;

    /// <summary>Text from an outside service: one short line, printable characters only.</summary>
    private static string Short(string text)
    {
        var clean = new string([.. text.Where(c => !char.IsControl(c))]).Trim();
        return clean.Length > 80 ? clean[..80] : clean;
    }

    /// <summary>A speed for people: "43.1 Mbit/s", "940 Mbit/s", "1.2 Gbit/s".</summary>
    public static string Format(double bitsPerSecond) => bitsPerSecond switch
    {
        >= 1e9 => (bitsPerSecond / 1e9).ToString("0.0#", CultureInfo.InvariantCulture) + " Gbit/s",
        >= 100e6 => (bitsPerSecond / 1e6).ToString("0", CultureInfo.InvariantCulture) + " Mbit/s",
        _ => (bitsPerSecond / 1e6).ToString("0.0", CultureInfo.InvariantCulture) + " Mbit/s",
    };
}
