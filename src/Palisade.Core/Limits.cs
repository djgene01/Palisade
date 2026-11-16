using System.Text.Json;

namespace Palisade.Core;

/// <summary>A device that may reach only the listed sites on the internet. Everything else it tries is refused.</summary>
public sealed class DeviceLimit
{
    public string Mac { get; set; } = "";
    public string Name { get; set; } = "";
    /// <summary>YouTube, with the Google services its apps need to start and sign in.</summary>
    public bool YouTube { get; set; }
    /// <summary>Further sites the owner allows, as plain names such as "netflix.com".</summary>
    public List<string> Sites { get; set; } = [];
}

/// <summary>
/// How a limit is enforced. The name server notes the addresses of each allowed site in a list as the
/// device looks them up; the firewall then lets that device reach only addresses on its list.
/// </summary>
public static class LimitPlan
{
    public const int MaxDevices = 50;
    public const int MaxSites = 50;

    // YouTube itself, then what its apps on a TV box need before they will play anything:
    // Google sign-in, app services, and the "am I online" check.
    public static readonly string[] YouTubeSites =
    [
        "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "youtube-nocookie.com",
        "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gvt1.com", "android.com",
    ];

    public static IReadOnlyList<string> Sites(DeviceLimit limit) =>
        [.. (limit.YouTube ? YouTubeSites : []).Concat(limit.Sites).Distinct()];

    /// <summary>The kernel list holding the addresses this device may reach.</summary>
    public static string SetName(string mac) =>
        ConfigValidator.TryNormalizeMac(mac, out var normal) && normal == mac
            ? "only_" + mac.Replace(":", "")
            : throw new InvalidOperationException($"Unsafe hardware address in config: {mac}");

    public static string Describe(DeviceLimit limit) => (limit.YouTube, limit.Sites.Count) switch
    {
        (true, 0) => "Only YouTube",
        (true, var n) => $"Only YouTube and {(n == 1 ? "1 site" : $"{n} sites")}",
        (false, 1) => $"Only {limit.Sites[0]}",
        (false, var n) => $"Only {n} sites",
    };

    public static List<ValidationIssue> Validate(IReadOnlyList<DeviceLimit> limits)
    {
        var issues = new List<ValidationIssue>();
        if (limits.Count > MaxDevices) issues.Add(new("Limits", $"At most {MaxDevices} devices can be limited to chosen sites."));
        var seen = new HashSet<string>();
        foreach (var limit in limits)
        {
            var field = $"Limit.{limit.Mac}";
            if (!ConfigValidator.TryNormalizeMac(limit.Mac, out var mac) || mac != limit.Mac) issues.Add(new(field, $"\"{limit.Mac}\" is not a valid hardware (MAC) address."));
            else if (!seen.Add(limit.Mac)) issues.Add(new(field, $"{limit.Mac} is limited twice. Keep one."));
            if (!ConfigValidator.IsSafeName(limit.Name)) issues.Add(new(field, "A limited device needs a short name using letters, numbers and spaces."));
            if (!limit.YouTube && limit.Sites.Count == 0) issues.Add(new(field, $"{limit.Name}: choose YouTube or add at least one site, or remove the limit."));
            if (limit.Sites.Count > MaxSites) issues.Add(new(field, $"{limit.Name}: at most {MaxSites} sites of your own can be allowed."));
            foreach (var site in limit.Sites)
                if (!SiteName.IsValid(site)) issues.Add(new(field, $"\"{site}\" is not a site name. Use a name like example.com."));
            if (limit.Sites.Distinct().Count() != limit.Sites.Count) issues.Add(new(field, $"{limit.Name}: the same site is listed twice."));
        }
        return issues;
    }

    /// <summary>Reads the addresses in one list from "nft -j list set", so they can be put back after the rules are reloaded.</summary>
    public static List<string> ParseAddresses(string json)
    {
        var result = new List<string>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("nftables", out var items)) return result;
            foreach (var item in items.EnumerateArray())
            {
                if (!item.TryGetProperty("set", out var set) || !set.TryGetProperty("elem", out var elems)) continue;
                foreach (var entry in elems.EnumerateArray())
                {
                    var val = entry.ValueKind == JsonValueKind.Object && entry.TryGetProperty("elem", out var elem) && elem.TryGetProperty("val", out var inner) ? inner : entry;
                    if (val.ValueKind == JsonValueKind.String && Ip4.TryParse(val.GetString(), out var ip)) result.Add(ip.ToString());
                }
            }
        }
        catch (JsonException)
        {
        }
        return result;
    }

    /// <summary>Puts remembered addresses back into their lists. Empty when there is nothing to put back.</summary>
    public static string RestoreScript(IReadOnlyDictionary<string, List<string>> remembered) =>
        string.Concat(remembered.Where(r => r.Value.Count > 0).Select(r =>
            $"add element inet palisade {SetName(r.Key)} {{ {string.Join(", ", r.Value.Select(a => Ip4.TryParse(a, out var ip) ? ip.ToString() : throw new InvalidOperationException("Unsafe address.")))} }}\n"));
}
