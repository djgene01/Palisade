using Microsoft.JSInterop;
using Palisade.UI.Services;

namespace Palisade.Web.Services;

/// <summary>
/// Asks from the browser's side. The page itself runs on the firewall, so only the owner's browser
/// can tell whether a new connection from where the owner sits still gets through.
/// </summary>
public sealed class BrowserProbe(IJSRuntime js, WebPorts ports) : IConnectionProbe
{
    public async Task<bool> CanReachAsync(CancellationToken ct = default)
    {
        try
        {
            return await js.InvokeAsync<bool>("palisade.checkReachable", ct, ports.Check);
        }
        catch (Exception ex) when (ex is JSException or JSDisconnectedException)
        {
            return false;
        }
    }

    public async Task<string> ClientAddressAsync(CancellationToken ct = default) =>
        await js.InvokeAsync<string>("palisade.whoAmI", ct);
}
