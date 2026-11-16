using System.Text.RegularExpressions;

namespace Palisade.Core;

/// <summary>Where the firewall's own software stands against the newest release.</summary>
public sealed class UpdateStatus
{
    /// <summary>The installed release, such as "v1.4". Empty when the software was copied on by hand.</summary>
    public string Current { get; set; } = "";
    /// <summary>The newest release found at the last check. Empty when no check has succeeded yet.</summary>
    public string Latest { get; set; } = "";
    public DateTimeOffset? CheckedAt { get; set; }
    public bool Auto { get; set; }
    /// <summary>True when an access key for a private repository is stored. The key itself is never sent back.</summary>
    public bool HasToken { get; set; }
    public bool Installing { get; set; }
    /// <summary>What went wrong at the last check or install, in plain words. Empty when nothing did.</summary>
    public string Problem { get; set; } = "";

    public bool InstalledByHand => Current.Length == 0;
    public bool Available => Latest.Length > 0 && Latest != Current;
}

public sealed class UpdateSettings
{
    public bool Auto { get; set; }
    /// <summary>Null leaves the stored access key alone. Empty removes it.</summary>
    public string? Token { get; set; }
}

public interface IUpdates
{
    Task<UpdateStatus> GetUpdateAsync(CancellationToken ct = default);
    Task<UpdateStatus> SetUpdateAsync(UpdateSettings settings, CancellationToken ct = default);
    /// <summary>Looks for a newer release, and installs it when asked to.</summary>
    Task<UpdateStatus> CheckUpdateAsync(bool install, CancellationToken ct = default);
}

public static partial class UpdatePlan
{
    public const string AssetName = "palisade-linux-x64.tar.gz";

    [GeneratedRegex(@"^[0-9A-Za-z][0-9A-Za-z._\-]{0,39}$")]
    private static partial Regex Tag();

    [GeneratedRegex(@"^[\x21-\x7e]{1,255}$")]
    private static partial Regex Token();

    [GeneratedRegex(@"^sha256:[0-9a-f]{64}$")]
    private static partial Regex Digest();

    /// <summary>A release name ends up in file paths and on screen, so only plain version-like text is accepted.</summary>
    public static bool IsTag(string? text) => text is not null && Tag().IsMatch(text);

    /// <summary>An access key goes into a request header: printable characters only, no spaces or line breaks.</summary>
    public static bool IsToken(string? text) => text is not null && Token().IsMatch(text);

    public static bool IsDigest(string? text) => text is not null && Digest().IsMatch(text);

    /// <summary>The release recorded at install time. Builds copied on by hand say "dev" and count as no release.</summary>
    public static string InstalledVersion(string? versionFile)
    {
        var text = (versionFile ?? "").Trim();
        return IsTag(text) && !text.StartsWith("dev", StringComparison.OrdinalIgnoreCase) ? text : "";
    }

    /// <summary>
    /// Automatic installs only move a released version to a newer release. Software copied on by hand is
    /// left alone, since it may be newer than anything released.
    /// </summary>
    public static bool ShouldAutoInstall(UpdateStatus status) => status is { Auto: true, Available: true, InstalledByHand: false };
}
