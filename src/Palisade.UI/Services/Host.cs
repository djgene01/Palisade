using Microsoft.Extensions.DependencyInjection;
using Palisade.Core;

namespace Palisade.UI.Services;

/// <summary>
/// How the screen in front of the owner reaches the firewall. A browser has to ask from its own side
/// of the connection; an app asks directly. Each host provides its own.
/// </summary>
public interface IConnectionProbe
{
    /// <summary>
    /// True when a brand-new connection still reaches the firewall. The connection already open keeps
    /// working even when a new rule would block the next visit, so only a fresh one proves nobody is locked out.
    /// </summary>
    Task<bool> CanReachAsync(CancellationToken ct = default);

    /// <summary>The address the firewall sees this screen connecting from, or empty when it is not known.</summary>
    Task<string> ClientAddressAsync(CancellationToken ct = default);
}

/// <summary>Who made a device, from its hardware address. Must answer at once: null when not (yet) known.</summary>
public interface IMakerSource
{
    string? Find(string mac);
}

/// <summary>Parts of the page frame that only the host can provide.</summary>
public sealed class ShellOptions
{
    /// <summary>
    /// A component that ends the session, or null when there is nothing to sign out of. It receives one
    /// parameter, <c>Sidebar</c>: true in the side menu, false in the footer shown on small screens.
    /// </summary>
    public Type? SignOutButton { get; init; }
}

public static class PalisadeUiServices
{
    /// <summary>
    /// Registers the shared screens' own services. The host must also register
    /// <see cref="IFirewallBackend"/>, <see cref="IUpdates"/>, <see cref="ITrafficWatch"/>, <see cref="IDnsControl"/>,
    /// <see cref="IConnectionProbe"/>, <see cref="IMakerSource"/> and <see cref="ShellOptions"/>.
    /// </summary>
    public static IServiceCollection AddPalisadeUi(this IServiceCollection services) =>
        services.AddScoped<FirewallState>();
}
