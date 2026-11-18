using System.Text.Json;
using Palisade.Client;

namespace Palisade.App.Services;

/// <summary>
/// The firewalls this device is linked to, and which one it shows. The links hold each firewall's token,
/// so they live in the phone's secure storage (the Android keystore, Windows data protection). Which one is
/// chosen is not secret and sits in ordinary preferences.
/// </summary>
public sealed class FirewallStore
{
    public const string Demo = "demo";
    private const string LinksKey = "palisade.links";
    private const string ChosenKey = "palisade.chosen";

    private readonly Lock _lock = new();
    private List<FirewallLink> _links = [];

    public IReadOnlyList<FirewallLink> Links { get { lock (_lock) return [.. _links]; } }

    /// <summary>The chosen firewall's device id, <see cref="Demo"/>, or null when nothing is chosen yet.</summary>
    public string? Chosen
    {
        get => Preferences.Default.Get<string?>(ChosenKey, null);
        set
        {
            if (value is null) Preferences.Default.Remove(ChosenKey);
            else Preferences.Default.Set(ChosenKey, value);
        }
    }

    public async Task LoadAsync()
    {
        var json = await SecureStorage.Default.GetAsync(LinksKey);
        List<FirewallLink> links;
        try { links = json is null ? [] : JsonSerializer.Deserialize<List<FirewallLink>>(json) ?? []; }
        // Unreadable after, say, restoring a backup onto another phone: the keys did not travel with it.
        catch (JsonException) { links = []; }
        lock (_lock) _links = links;
    }

    /// <summary>Keeps a new link, replacing an older one to the same firewall, and chooses it.</summary>
    public async Task AddAsync(FirewallLink link)
    {
        lock (_lock)
        {
            _links.RemoveAll(l => l.Host == link.Host && l.Port == link.Port || l.DeviceId == link.DeviceId);
            _links.Add(link);
        }
        await SaveAsync();
        Chosen = link.DeviceId;
    }

    public async Task RemoveAsync(string deviceId)
    {
        lock (_lock) _links.RemoveAll(l => l.DeviceId == deviceId);
        await SaveAsync();
        if (Chosen == deviceId) Chosen = null;
    }

    private Task SaveAsync()
    {
        string json;
        lock (_lock) json = JsonSerializer.Serialize(_links);
        return SecureStorage.Default.SetAsync(LinksKey, json);
    }
}
