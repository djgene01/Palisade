using Palisade.Client;

namespace Palisade.App.Services;

/// <summary>
/// Holds the page that something outside the app asked for (a pairing link, a share, a shortcut) until the
/// screens can open it. What is accepted is decided in <see cref="IncomingLinks"/>.
/// </summary>
public sealed class AppLinks
{
    private string? _pending;

    /// <summary>Raised when something arrived while the app was already open.</summary>
    public event Action? Arrived;

    /// <summary>The page to open, once. Null when nothing is waiting.</summary>
    public string? Take() => Interlocked.Exchange(ref _pending, null);

    public void OpenLink(string? link) => Open(IncomingLinks.PageFor(link));

    public void Shared(string? text) => Open(IncomingLinks.PageForShared(text));

    private void Open(string? page)
    {
        if (page is null) return;
        _pending = page;
        Arrived?.Invoke();
    }
}
