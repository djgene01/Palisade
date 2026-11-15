using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Palisade.Core;

/// <summary>When one device may use the internet. Keyed by hardware address, like the content filter.</summary>
public sealed class DeviceAccess
{
    public string Mac { get; set; } = "";
    public string Name { get; set; } = "";
    /// <summary>Switched off by hand. With <see cref="PausedUntil"/> empty it stays off until someone resumes it.</summary>
    public bool Paused { get; set; }
    public DateTimeOffset? PausedUntil { get; set; }
    /// <summary>Regular times the internet is off for this device, such as bedtime.</summary>
    public List<OffTime> OffTimes { get; set; } = [];
}

/// <summary>A stretch of the day, on the given days, when the internet is off. "To" at or before "From" means it runs past midnight.</summary>
public sealed class OffTime
{
    public string Id { get; set; } = NewId.Create();
    /// <summary>The days the stretch starts on.</summary>
    public List<DayOfWeek> Days { get; set; } = [];
    public string From { get; set; } = "21:00";
    public string To { get; set; } = "07:00";
}

public static partial class AccessPlan
{
    public const string PausedSet = "paused";

    [GeneratedRegex(@"^([01][0-9]|2[0-3]):[0-5][0-9]$")]
    private static partial Regex ClockTime();

    public static bool TryParseTime(string? text, out TimeSpan time)
    {
        time = default;
        if (text is null || !ClockTime().IsMatch(text)) return false;
        time = new TimeSpan(int.Parse(text[..2], CultureInfo.InvariantCulture), int.Parse(text[3..], CultureInfo.InvariantCulture), 0);
        return true;
    }

    public static bool IsPausedByHand(DeviceAccess device, DateTimeOffset now) =>
        device.Paused && (device.PausedUntil is not { } until || until > now);

    /// <summary>The scheduled stretch that covers this moment on the firewall's own clock, if any.</summary>
    public static OffTime? CurrentOffTime(DeviceAccess device, DateTime localNow)
    {
        var day = localNow.DayOfWeek;
        var yesterday = (DayOfWeek)(((int)day + 6) % 7);
        var time = localNow.TimeOfDay;
        foreach (var off in device.OffTimes)
        {
            if (!TryParseTime(off.From, out var from) || !TryParseTime(off.To, out var to) || from == to) continue;
            if (to > from)
            {
                if (off.Days.Contains(day) && time >= from && time < to) return off;
            }
            // Past midnight: the evening part belongs to the day it started, the morning part to the day before.
            else if ((off.Days.Contains(day) && time >= from) || (off.Days.Contains(yesterday) && time < to)) return off;
        }
        return null;
    }

    public static bool IsOff(DeviceAccess device, DateTimeOffset now, DateTime localNow) =>
        IsPausedByHand(device, now) || CurrentOffTime(device, localNow) is not null;

    /// <summary>The hardware addresses that must be cut off right now, in a stable order.</summary>
    public static List<string> OffNow(IEnumerable<DeviceAccess> access, DateTimeOffset now, DateTime localNow) =>
        [.. access.Where(d => IsOff(d, now, localNow)).Select(d => d.Mac).Distinct().Order(StringComparer.Ordinal)];

    /// <summary>
    /// The nft commands that make the kernel's set equal to the list. Emptying and refilling happen in one
    /// file, which nft applies as a single step, so there is never a moment with a half-filled set.
    /// </summary>
    public static string SetScript(IReadOnlyCollection<string> macs)
    {
        var sb = new StringBuilder();
        sb.Append($"flush set inet palisade {PausedSet}\n");
        if (macs.Count > 0)
        {
            foreach (var mac in macs)
                if (!ConfigValidator.TryNormalizeMac(mac, out var normal) || normal != mac)
                    throw new InvalidOperationException($"Unsafe hardware address: {mac}");
            sb.Append($"add element inet palisade {PausedSet} {{ {string.Join(", ", macs)} }}\n");
        }
        return sb.ToString();
    }

    public static List<ValidationIssue> Validate(IReadOnlyList<DeviceAccess> access)
    {
        var issues = new List<ValidationIssue>();
        if (access.Count > 200) issues.Add(new("Access", "At most 200 devices can be paused or have a schedule."));
        var seen = new HashSet<string>();
        foreach (var device in access)
        {
            var field = $"Access.{device.Mac}";
            void Add(string message) => issues.Add(new(field, message));
            if (!ConfigValidator.TryNormalizeMac(device.Mac, out var mac) || mac != device.Mac) Add($"\"{device.Mac}\" is not a valid hardware (MAC) address.");
            else if (!seen.Add(device.Mac)) Add($"{device.Mac} is listed twice.");
            if (!ConfigValidator.IsSafeName(device.Name)) Add("A paused or scheduled device needs a short name using letters, numbers and spaces.");
            if (device.OffTimes.Count > 12) Add($"{device.Name}: a device can have at most 12 off times.");
            foreach (var off in device.OffTimes)
            {
                if (off.Days.Count == 0) Add($"{device.Name}: choose at least one day for each off time.");
                if (off.Days.Any(d => !Enum.IsDefined(d)) || off.Days.Distinct().Count() != off.Days.Count) Add($"{device.Name}: the days of an off time are not valid.");
                var fromOk = TryParseTime(off.From, out var from);
                var toOk = TryParseTime(off.To, out var to);
                if (!fromOk || !toOk) Add($"{device.Name}: times must look like 21:00.");
                else if (from == to) Add($"{device.Name}: an off time can't start and end at the same minute.");
            }
        }
        return issues;
    }
}
