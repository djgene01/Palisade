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
    /// A component without parameters that ends the session, or null when there is nothing to sign out of.
    /// It is shown in the side menu on wide screens and in the More menu on phones.
    /// </summary>
    public Type? SignOutButton { get; init; }

    /// <summary>
    /// Extra sections for the Advanced page that only this host can offer, such as linking phones on the
    /// firewall itself. Each is a component without parameters, shown after the updates section.
    /// </summary>
    public IReadOnlyList<Type> AdvancedSections { get; init; } = [];

    /// <summary>
    /// True when the screens run on the firewall itself, as the web interface does. Then "can't reach the
    /// firewall" means its own service is down, and the help points at that; the app shows its own message.
    /// </summary>
    public bool OnTheFirewall { get; init; } = true;

    /// <summary>Menu entries only this host has, such as the app's list of firewalls. Shown after the pages.</summary>
    public IReadOnlyList<ShellLink> ExtraLinks { get; init; } = [];

    /// <summary>The line under the name in the page frame, such as which firewall the app is showing.</summary>
    public Func<string> Subtitle { get; init; } = () => "Home firewall";

    /// <summary>Told whenever the page switches between light and dark, so the host can colour what is around it.</summary>
    public Action<bool>? ThemeChanged { get; init; }

    /// <summary>
    /// True in an app, which the phone may pause when the owner switches away. Paused, it cannot confirm a change,
    /// and the firewall undoes it after a minute, so the screens ask the owner to stay until it is confirmed.
    /// </summary>
    public bool CanBePaused { get; init; }
}

public sealed record ShellLink(string Href, string Label, string Icon);

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
