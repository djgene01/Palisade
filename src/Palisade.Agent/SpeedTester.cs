using System.Diagnostics;
using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using Palisade.Core;

namespace Palisade.Agent;

/// <summary>
/// Tests the internet connection with Speedtest by Ookla: on a schedule, put off while the household is busy, and
/// whenever the owner asks. Ookla's program is fetched from Ookla on the first test (it may not be shipped with
/// Palisade) and only ever run when it is exactly the file Palisade was built against.
/// </summary>
public sealed class SpeedTester(string dataDirectory, ISystemPlatform platform, ILogger<SpeedTester> log) : ISpeedTest, IAsyncDisposable
{
    private sealed class Saved
    {
        public SpeedSettings Settings { get; set; } = new();
        public List<SpeedResult> History { get; set; } = [];
    }

    private static readonly TimeSpan Every = TimeSpan.FromSeconds(30), Limit = TimeSpan.FromMinutes(2);
    private readonly Lock _gate = new();
    private readonly CancellationTokenSource _stop = new();
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(60) };
    private Saved _saved = new();
    private bool _running;
    private DateTimeOffset? _next;
    private string _postponed = "";
    private Task? _loop;

    private string Folder => Path.Combine(dataDirectory, "speedtest");
    private string Program => Path.Combine(Folder, "speedtest");
    private string SavedFile => Path.Combine(dataDirectory, "speed.json");

    public void Start()
    {
        try
        {
            if (File.Exists(SavedFile)) _saved = JsonSerializer.Deserialize<Saved>(File.ReadAllText(SavedFile), PalisadeJson.Options) ?? new();
        }
        catch (Exception e) when (e is JsonException or IOException)
        {
            log.LogWarning("The saved speed tests could not be read, so they start afresh: {Error}", e.Message);
        }
        // After a restart the schedule carries on from the last test; a first one waits a little, not to clash with start-up.
        _next = _saved.History.FirstOrDefault() is { } last
            ? Max(last.At + Interval, DateTimeOffset.UtcNow + TimeSpan.FromMinutes(1))
            : DateTimeOffset.UtcNow + TimeSpan.FromMinutes(2);
        _loop = RunLoopAsync(_stop.Token);
    }

    private TimeSpan Interval => TimeSpan.FromMinutes(SpeedPlan.Intervals.Contains(_saved.Settings.IntervalMinutes) ? _saved.Settings.IntervalMinutes : SpeedPlan.DefaultInterval);

    private static DateTimeOffset Max(DateTimeOffset a, DateTimeOffset b) => a > b ? a : b;

    private async Task RunLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(Every);
        try
        {
            while (await timer.WaitForNextTickAsync(ct))
            {
                bool due;
                lock (_gate)
                    due = _saved.Settings is { Enabled: true, TermsAcceptedAt: not null } && !_running && DateTimeOffset.UtcNow >= _next;
                if (!due) continue;
                try
                {
                    // A test fills the line for half a minute: not while someone is on a call or watching a film.
                    if (SpeedPlan.IsBusy(await platform.GetUsageAsync(ct), _saved.History.FirstOrDefault()))
                    {
                        lock (_gate)
                        {
                            _postponed = "Put off because the internet was in use. Tried again every 5 minutes until it is quiet.";
                            _next = DateTimeOffset.UtcNow + SpeedPlan.RetryAfterBusy;
                        }
                        continue;
                    }
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    log.LogWarning("Could not tell whether the internet is in use; testing anyway: {Error}", e.Message);
                }
                await RunAsync(SpeedPlan.Scheduled, ct);
            }
        }
        catch (OperationCanceledException) { }
    }

    public Task<SpeedStatus> GetSpeedAsync(CancellationToken ct = default) => Task.FromResult(Status());

    public async Task<SpeedStatus> SetSpeedAsync(SpeedSettingsRequest request, CancellationToken ct = default)
    {
        lock (_gate)
        {
            if (SpeedPlan.Validate(request, _saved.Settings) is { } problem) return Status(problem);
            var settings = _saved.Settings;
            if (request.AcceptTerms && settings.TermsAcceptedAt is null) settings.TermsAcceptedAt = DateTimeOffset.UtcNow;
            var switchedOn = request.Enabled && !settings.Enabled;
            (settings.Enabled, settings.IntervalMinutes) = (request.Enabled, request.IntervalMinutes);
            _postponed = "";
            // Switched on: the first test soon. A new interval counts from the last test.
            _next = switchedOn || _saved.History.Count == 0
                ? DateTimeOffset.UtcNow + TimeSpan.FromMinutes(1)
                : Max(_saved.History[0].At + Interval, DateTimeOffset.UtcNow + TimeSpan.FromMinutes(1));
        }
        await SaveAsync(ct);
        return Status();
    }

    public Task<SpeedStatus> RunSpeedTestAsync(CancellationToken ct = default)
    {
        lock (_gate)
        {
            if (_saved.Settings.TermsAcceptedAt is null) return Task.FromResult(Status("Tests use Speedtest by Ookla. Accept Ookla's terms first."));
            if (_running) return Task.FromResult(Status());
            _running = true;
        }
        // The page asks again every few seconds; a test takes about half a minute.
        _ = Task.Run(() => RunAsync(SpeedPlan.Manual, _stop.Token, alreadyMarked: true));
        return Task.FromResult(Status());
    }

    private async Task RunAsync(string trigger, CancellationToken ct, bool alreadyMarked = false)
    {
        if (!alreadyMarked)
            lock (_gate)
            {
                if (_running) return;
                _running = true;
            }
        var at = DateTimeOffset.UtcNow;
        SpeedResult result;
        try
        {
            await EnsureProgramAsync(ct);
            result = SpeedPlan.Parse(await RunProgramAsync(ct), at, trigger);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { lock (_gate) _running = false; return; }
        catch (Exception e)
        {
            log.LogWarning("The speed test could not run: {Error}", e.Message);
            result = new SpeedResult { At = at, Trigger = trigger, Problem = e is SpeedTestException ? e.Message : "The speed test could not run. Is the internet reachable?" };
        }
        lock (_gate)
        {
            _saved.History.Insert(0, result);
            _saved.History.RemoveAll(r => DateTimeOffset.UtcNow - r.At > SpeedPlan.Kept);
            _running = false;
            _postponed = "";
            _next = DateTimeOffset.UtcNow + Interval;
        }
        try { await SaveAsync(CancellationToken.None); }
        catch (IOException e) { log.LogWarning("Saving the speed tests failed: {Error}", e.Message); }
    }

    private sealed class SpeedTestException(string message) : Exception(message);

    /// <summary>Fetches Ookla's program the first time, and refuses to run anything but the exact file Palisade expects.</summary>
    private async Task EnsureProgramAsync(CancellationToken ct)
    {
        // Checked before every test, not once: a 2.6 MB hash costs milliseconds, and a file changed since is caught.
        if (File.Exists(Program) && ProgramHash is { Length: 64 } expected && await HashAsync(Program, ct) == expected) return;

        byte[] archive;
        try { archive = await _http.GetByteArrayAsync(SpeedPlan.CliUrl, ct); }
        catch (HttpRequestException e) { throw new SpeedTestException($"Ookla's speed test program could not be downloaded ({e.Message}). Is the internet reachable?"); }
        if (archive.Length != SpeedPlan.CliSize || Convert.ToHexStringLower(SHA256.HashData(archive)) != SpeedPlan.CliSha256)
            throw new SpeedTestException("The speed test program from Ookla was not the expected file, so it was not used.");

        Directory.CreateDirectory(Folder);
        await using var gzip = new GZipStream(new MemoryStream(archive), CompressionMode.Decompress);
        using var tar = new TarReader(gzip);
        while (await tar.GetNextEntryAsync(cancellationToken: ct) is { } entry)
        {
            if (entry.Name != "speedtest" || entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile) || entry.DataStream is null) continue;
            var temp = Program + ".palisade-tmp";
            await using (var file = File.Create(temp)) await entry.DataStream.CopyToAsync(file, ct);
            File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            File.Move(temp, Program, overwrite: true);
            ProgramHash = await HashAsync(Program, ct);
            return;
        }
        throw new SpeedTestException("Ookla's download did not contain the speed test program.");
    }

    // The unpacked program's own hash, remembered once the archive it came from checked out.
    private string ProgramHash
    {
        get => File.Exists(ProgramHashFile) ? File.ReadAllText(ProgramHashFile).Trim() : "";
        set => File.WriteAllText(ProgramHashFile, value);
    }

    private string ProgramHashFile => Path.Combine(Folder, "speedtest.sha256");

    private static async Task<string> HashAsync(string path, CancellationToken ct)
    {
        await using var file = File.OpenRead(path);
        return Convert.ToHexStringLower(await SHA256.HashDataAsync(file, ct));
    }

    private async Task<string> RunProgramAsync(CancellationToken ct)
    {
        var start = new ProcessStartInfo(Program)
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false,
            // The owner accepted Ookla's terms on the page; the program keeps its own settings in its folder.
            ArgumentList = { "--accept-license", "--accept-gdpr", "--format=json", "--progress=no" },
            Environment = { ["HOME"] = Folder },
        };
        using var process = Process.Start(start) ?? throw new SpeedTestException("The speed test program did not start.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(Limit);
        var output = process.StandardOutput.ReadToEndAsync(timeout.Token);
        var errors = process.StandardError.ReadToEndAsync(timeout.Token);
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            process.Kill(entireProcessTree: true);
            throw new SpeedTestException("The speed test took longer than two minutes and was stopped.");
        }
        return await output + "\n" + await errors;
    }

    private SpeedStatus Status(string problem = "")
    {
        lock (_gate)
            return new SpeedStatus
            {
                Settings = new SpeedSettings { Enabled = _saved.Settings.Enabled, IntervalMinutes = _saved.Settings.IntervalMinutes, TermsAcceptedAt = _saved.Settings.TermsAcceptedAt },
                Installed = File.Exists(Program), Running = _running,
                NextAt = _saved.Settings is { Enabled: true, TermsAcceptedAt: not null } ? _next : null,
                Postponed = _postponed, History = SpeedPlan.ForWire(_saved.History), Problem = problem,
            };
    }

    private async Task SaveAsync(CancellationToken ct)
    {
        string json;
        lock (_gate) json = JsonSerializer.Serialize(_saved, PalisadeJson.Options);
        Directory.CreateDirectory(dataDirectory);
        var temp = SavedFile + ".palisade-tmp";
        await File.WriteAllTextAsync(temp, json, ct);
        File.Move(temp, SavedFile, overwrite: true);
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        if (_loop is not null) await _loop;
        _http.Dispose();
        _stop.Dispose();
    }
}
