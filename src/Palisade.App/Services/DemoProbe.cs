using Palisade.UI.Services;

namespace Palisade.App.Services;

/// <summary>
/// For the demo firewall, which runs inside the app itself: it is always reachable, and the
/// "connection" comes from nowhere in particular. A real firewall gets a probe that opens a fresh
/// connection to it instead.
/// </summary>
public sealed class DemoProbe : IConnectionProbe
{
    public Task<bool> CanReachAsync(CancellationToken ct = default) => Task.FromResult(true);

    public Task<string> ClientAddressAsync(CancellationToken ct = default) => Task.FromResult("");
}

/// <summary>The demo has no way to look device makers up, and needs none.</summary>
public sealed class NoMakers : IMakerSource
{
    public string? Find(string mac) => null;
}
