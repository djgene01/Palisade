using Palisade.UI.Services;

namespace Palisade.App.Services;

/// <summary>
/// For the demo firewall, which runs inside the app itself: it is always reachable, and the
/// "connection" comes from nowhere in particular.
/// </summary>
public sealed class DemoProbe : IConnectionProbe
{
    public Task<bool> CanReachAsync(CancellationToken ct = default) => Task.FromResult(true);

    public Task<string> ClientAddressAsync(CancellationToken ct = default) => Task.FromResult("");
}
