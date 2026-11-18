using Microsoft.AspNetCore.Components;
using Palisade.Client;
using Palisade.UI.Services;

namespace Palisade.App.Services;

/// <summary>
/// The one way the app changes which firewall it shows. It swaps the backend, forgets everything the screens
/// had loaded, remembers the choice, loads afresh and opens the overview. Doing this in one place means no screen
/// can ever show one firewall's settings under another's name.
/// </summary>
public sealed class FirewallSwitcher(ActiveFirewall active, FirewallStore store, FirewallState state, NavigationManager nav)
{
    public Task ShowAsync(FirewallLink link) => SwitchAsync(() => active.Show(link), link.DeviceId);

    public Task ShowDemoAsync() => SwitchAsync(active.ShowDemo, FirewallStore.Demo);

    /// <summary>Keeps a new link and shows it. An older link to the same firewall is told to stop working there.</summary>
    public async Task AddAndShowAsync(FirewallLink link)
    {
        foreach (var old in store.Links.Where(l => l.Host == link.Host && l.Port == link.Port && l.DeviceId != link.DeviceId))
            await UnpairQuietlyAsync(old);
        await store.AddAsync(link);
        await ShowAsync(link);
    }

    /// <summary>
    /// Forgets a link here, after asking the firewall to forget this device too. Returns false when the firewall
    /// could not be reached to be told, so the owner knows to remove the device on its page.
    /// </summary>
    public async Task<bool> UnlinkAsync(FirewallLink link)
    {
        var told = await UnpairQuietlyAsync(link);
        await store.RemoveAsync(link.DeviceId);
        if (active.Link?.DeviceId == link.DeviceId)
        {
            active.ShowNothing();
            state.Reset();
        }
        return told;
    }

    private static async Task<bool> UnpairQuietlyAsync(FirewallLink link)
    {
        try
        {
            using var backend = new RemoteBackend(link);
            await backend.UnpairAsync();
            return true;
        }
        catch (LinkRemovedException) { return true; }   // Already gone there.
        catch (FirewallException) { return false; }
    }

    private async Task SwitchAsync(Action show, string chosen)
    {
        show();
        store.Chosen = chosen;
        state.Reset();
        await state.LoadAsync();
        nav.NavigateTo("/");
    }
}
