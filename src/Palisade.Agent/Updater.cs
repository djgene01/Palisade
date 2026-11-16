using System.Diagnostics;
using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Palisade.Core;

namespace Palisade.Agent;

/// <summary>
/// Keeps Palisade itself up to date from the releases published on its GitHub repository.
/// A release is trusted because it comes from that repository over HTTPS and matches the checksum
/// GitHub recorded for it: whoever can publish a release there can change what this firewall runs.
/// </summary>
public sealed class Updater(string dataDirectory, string repository, ILogger<Updater> log) : IUpdates
{
    private const string VersionFile = "/opt/palisade/VERSION";
    private const long MaxDownload = 400L * 1024 * 1024;

    private sealed record Saved(bool Auto, string Token);
    private sealed record Release(string Tag, string AssetUrl, string Digest);

    private readonly string _settingsPath = Path.Combine(dataDirectory, "update.json");
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromMinutes(10) };
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly UpdateStatus _status = new();
    private Release? _latest;

    private Saved Load()
    {
        try
        {
            if (File.Exists(_settingsPath))
                return JsonSerializer.Deserialize<Saved>(File.ReadAllText(_settingsPath), PalisadeJson.Options) ?? new(false, "");
        }
        catch (Exception ex) { log.LogWarning("Update settings could not be read: {Message}", ex.Message); }
        return new(false, "");
    }

    private UpdateStatus Snapshot()
    {
        var saved = Load();
        return new UpdateStatus
        {
            Current = UpdatePlan.InstalledVersion(File.Exists(VersionFile) ? File.ReadAllText(VersionFile) : ""),
            Latest = _status.Latest, CheckedAt = _status.CheckedAt, Installing = _status.Installing, Problem = _status.Problem,
            Auto = saved.Auto, HasToken = saved.Token.Length > 0,
        };
    }

    public Task<UpdateStatus> GetUpdateAsync(CancellationToken ct = default) => Task.FromResult(Snapshot());

    public async Task<UpdateStatus> SetUpdateAsync(UpdateSettings settings, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var token = settings.Token is null ? Load().Token : settings.Token.Trim();
            if (token.Length > 0 && !UpdatePlan.IsToken(token))
            {
                _status.Problem = "That access key has characters a key can't contain. Copy it again from GitHub.";
                return Snapshot();
            }
            var temp = _settingsPath + ".tmp";
            await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(new Saved(settings.Auto, token), PalisadeJson.Options), ct);
            // The access key is a secret: only root may read the file.
            File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.Move(temp, _settingsPath, overwrite: true);
            _status.Problem = "";
            return Snapshot();
        }
        finally { _gate.Release(); }
    }

    public async Task<UpdateStatus> CheckUpdateAsync(bool install, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await FindLatestAsync(ct);
            if (install && _latest is { } release && Snapshot().Available) await InstallAsync(release, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _status.Problem = $"The update did not go through. ({ex.Message})";
            log.LogWarning("Update failed: {Message}", ex.Message);
        }
        finally { _gate.Release(); }
        return Snapshot();
    }

    private HttpRequestMessage Request(string url, string accept)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("Palisade-updater", "1"));
        request.Headers.Accept.ParseAdd(accept);
        var token = Load().Token;
        if (token.Length > 0) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return request;
    }

    private async Task FindLatestAsync(CancellationToken ct)
    {
        _latest = null;
        using var response = await _http.SendAsync(Request($"https://api.github.com/repos/{repository}/releases/latest", "application/vnd.github+json"), ct);
        _status.CheckedAt = DateTimeOffset.UtcNow;
        if ((int)response.StatusCode is 401 or 403 or 404)
        {
            _status.Problem = Load().Token.Length > 0
                ? "GitHub refused the access key, or no release has been published yet."
                : "No release was found. If the repository is private, the firewall needs an access key to read it.";
            return;
        }
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var tag = json.RootElement.GetProperty("tag_name").GetString();
        if (!UpdatePlan.IsTag(tag))
        {
            _status.Problem = "The newest release has a name Palisade does not accept.";
            return;
        }
        foreach (var asset in json.RootElement.GetProperty("assets").EnumerateArray())
        {
            if (asset.GetProperty("name").GetString() != UpdatePlan.AssetName) continue;
            var digest = asset.TryGetProperty("digest", out var d) ? d.GetString() : null;
            _latest = new Release(tag!, asset.GetProperty("url").GetString() ?? "", digest ?? "");
        }
        if (_latest is null)
        {
            _status.Problem = $"Release {tag} has no {UpdatePlan.AssetName} file, so it can't be installed.";
            return;
        }
        _status.Latest = tag!;
        _status.Problem = "";
    }

    private async Task InstallAsync(Release release, CancellationToken ct)
    {
        if (!release.AssetUrl.StartsWith($"https://api.github.com/repos/{repository}/", StringComparison.Ordinal) || !UpdatePlan.IsDigest(release.Digest))
        {
            _status.Problem = "The release came without a checksum to verify it by, so it was not installed.";
            return;
        }
        var folder = Path.Combine(dataDirectory, "update");
        if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true);
        Directory.CreateDirectory(folder);
        var archive = Path.Combine(folder, UpdatePlan.AssetName);

        using (var response = await _http.SendAsync(Request(release.AssetUrl, "application/octet-stream"), HttpCompletionOption.ResponseHeadersRead, ct))
        {
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength > MaxDownload) throw new InvalidOperationException("The release file is far larger than expected.");
            await using var file = File.Create(archive);
            await using var body = await response.Content.ReadAsStreamAsync(ct);
            var buffer = new byte[81920];
            long total = 0;
            int read;
            while ((read = await body.ReadAsync(buffer, ct)) > 0)
            {
                if ((total += read) > MaxDownload) throw new InvalidOperationException("The release file is far larger than expected.");
                await file.WriteAsync(buffer.AsMemory(0, read), ct);
            }
        }

        await using (var file = File.OpenRead(archive))
        {
            var actual = "sha256:" + Convert.ToHexStringLower(await SHA256.HashDataAsync(file, ct));
            if (actual != release.Digest)
            {
                File.Delete(archive);
                _status.Problem = "The downloaded release did not match its checksum, so it was not installed.";
                return;
            }
        }

        await RunAsync("tar", ["-xzf", archive, "-C", folder, "--no-same-owner"], ct);
        var installer = Path.Combine(folder, "palisade", "install.sh");
        if (!File.Exists(installer)) throw new InvalidOperationException("The release has no installer inside.");

        // The installer stops and replaces this very program, so it has to run outside it.
        var unit = "palisade-update-" + DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        await RunAsync("systemd-run", ["--unit", unit, "--collect", "--quiet", "sh", installer], ct);
        _status.Installing = true;
        _status.Problem = "";
        log.LogInformation("Installing release {Tag}.", release.Tag);
    }

    private static async Task RunAsync(string program, string[] arguments, CancellationToken ct)
    {
        var start = new ProcessStartInfo(program) { RedirectStandardError = true, UseShellExecute = false };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException($"{program} could not be started.");
        var error = await process.StandardError.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);
        if (process.ExitCode != 0) throw new InvalidOperationException($"{program} failed: {error.Trim()}");
    }

    /// <summary>Looks for a release shortly after starting, then once a night at a quiet hour, installing it when that is switched on.</summary>
    public async Task WatchAsync(CancellationToken ct)
    {
        var checkedOn = DateOnly.MinValue;
        try
        {
            await Task.Delay(TimeSpan.FromMinutes(2), ct);
            await CheckUpdateAsync(install: false, ct);
            using var timer = new PeriodicTimer(TimeSpan.FromMinutes(20));
            while (await timer.WaitForNextTickAsync(ct))
            {
                var now = DateTime.Now;
                if (now.Hour != 3 || checkedOn == DateOnly.FromDateTime(now)) continue;
                checkedOn = DateOnly.FromDateTime(now);
                var status = await CheckUpdateAsync(install: false, ct);
                if (UpdatePlan.ShouldAutoInstall(status)) await CheckUpdateAsync(install: true, ct);
            }
        }
        catch (OperationCanceledException) { }
    }
}
