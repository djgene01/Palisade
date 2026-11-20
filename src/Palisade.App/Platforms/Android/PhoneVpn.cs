using System.Text.Json;
using Palisade.Core;
using Palisade.UI.Services;

namespace Palisade.App.Services;

/// <summary>
/// The app's own VPN tunnel to the firewall it is showing. The key is made here and the private half is kept only in
/// this phone's secure storage (Android's keystore), per firewall. The firewall is told the public half over the paired
/// connection. The tunnel itself is WireGuard's own engine (<see cref="PhoneTunnel"/>).
/// </summary>
public sealed partial class PhoneVpn(ActiveFirewall active) : IPhoneVpn
{
    private sealed record Saved(string DeviceId, string Name, string Config);

    private Saved? _saved;
    private DateTime _setUpAt;
    private string? _savedFor;
    private PhoneVpnState _state = PhoneVpnState.NotSetUp;
    private string _problem = "";

    public event Action? Changed;

    public PhoneVpnStatus Status
    {
        get
        {
            var (rx, tx) = _state == PhoneVpnState.On ? PhoneTunnel.Traffic() : (0L, 0L);
            return new PhoneVpnStatus(_state, _saved?.DeviceId ?? "", _saved?.Name ?? "", rx, tx, _problem);
        }
    }

    public string DefaultName
    {
        get
        {
            var name = System.Text.RegularExpressions.Regex.Replace(DeviceInfo.Current.Name ?? "", "[^A-Za-z0-9 ]+", " ").Trim();
            return name.Length is > 0 and <= 40 ? name : name.Length > 40 ? name[..40].Trim() : "This phone";
        }
    }

    // One tunnel for the whole phone, so it belongs to the firewall it was set up for, whichever one is shown now.
    private string? Key => active.Link is { } link ? $"vpn:{link.DeviceId}" : null;

    private async Task LoadAsync()
    {
        if (Key == _savedFor) return;
        _savedFor = Key;
        _saved = null;
        if (Key is null) return;
        try
        {
            if (await SecureStorage.Default.GetAsync(Key) is { Length: > 0 } json) _saved = JsonSerializer.Deserialize<Saved>(json);
        }
        catch (Exception) { _saved = null; }   // Unreadable after a restore to another phone: set up afresh.
    }

    public async Task<IReadOnlyList<ValidationIssue>> SetUpAsync(string name)
    {
        if (Key is not { } key) return [new("", "Choose a linked firewall first: the demo has no VPN to join.")];
        var (privateKey, publicKey) = PhoneTunnel.NewKeys();
        VpnDeviceResult result;
        try { result = await active.AddVpnDeviceAsync(new VpnDeviceRequest { Name = name, Access = VpnAccess.HomeAndInternet, PublicKey = publicKey }); }
        catch (Exception ex) { return [new("", Problem.Explain(ex, "The firewall did not answer, so this phone was not added."))]; }
        if (!result.Ok) return result.Issues;

        // A firewall from before v1.9 ignores the phone's key and sends its own instead. That works too: the settings
        // then hold the key it made, and the phone keeps them just the same.
        var config = result.Device?.PublicKey == publicKey ? VpnPlan.WithPrivateKey(result.ClientConfig, privateKey) : result.ClientConfig;
        _saved = new Saved(result.Device!.Id, result.Device.Name, config);
        _savedFor = key;
        _setUpAt = DateTime.UtcNow;
        await SecureStorage.Default.SetAsync(key, JsonSerializer.Serialize(_saved));
        Set(PhoneVpnState.Off);
        return [];
    }

    public async Task<string?> ConnectAsync()
    {
        await LoadAsync();
        if (_saved is null) return "Set this phone up for the VPN first.";
        Set(PhoneVpnState.Connecting);
        var problem = await PhoneTunnel.UpAsync(_saved.Config);
        if (problem is null && !await PhoneTunnel.HomeAnswersAsync(TimeSpan.FromSeconds(15)))
        {
            // Everything is routed into the tunnel, so a home that doesn't answer means no internet at all: back off.
            await PhoneTunnel.DownAsync();
            problem = "Home didn't answer, so the VPN was switched off again and your internet works as before. Check that the VPN is on at the firewall, and that its line check says ready.";
        }
        Set(problem is null ? PhoneVpnState.On : PhoneVpnState.Off, problem ?? "");
        return problem;
    }

    public async Task DisconnectAsync()
    {
        await PhoneTunnel.DownAsync();
        Set(_saved is null ? PhoneVpnState.NotSetUp : PhoneVpnState.Off);
    }

    public async Task ForgetAsync()
    {
        await PhoneTunnel.DownAsync();
        if (Key is { } key) SecureStorage.Default.Remove(key);
        _saved = null;
        Set(PhoneVpnState.NotSetUp);
    }

    public async Task RefreshAsync(FirewallConfig? config)
    {
        await LoadAsync();
        // Removed on the firewall (lost, or from another screen): its key is useless now, so let it go here too.
        if (_saved is not null && config is { Vpn.Enabled: true } && config.Vpn.Devices.All(d => d.Id != _saved.DeviceId)
            && DateTime.UtcNow - _setUpAt > TimeSpan.FromMinutes(1))
        {
            await ForgetAsync();
            Set(PhoneVpnState.NotSetUp, "This phone was removed from the VPN on the firewall. Set it up again to use it.");
            return;
        }
        var up = PhoneTunnel.IsUp;
        Set(_saved is null ? PhoneVpnState.NotSetUp : up ? PhoneVpnState.On : _state == PhoneVpnState.Connecting ? PhoneVpnState.Connecting : PhoneVpnState.Off, _problem);
    }

    private void Set(PhoneVpnState state, string problem = "")
    {
        (_state, _problem) = (state, problem);
        Changed?.Invoke();
    }
}
