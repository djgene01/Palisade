using Microsoft.AspNetCore.Components;
using Palisade.Core;
using Palisade.Web.Services;

namespace Palisade.Web.Components.Shared;

/// <summary>Base for pages that show firewall state: re-renders whenever the shared state changes.</summary>
public abstract class StatePage : ComponentBase, IDisposable
{
    [Inject] protected FirewallState State { get; set; } = default!;

    /// <summary>The layout only renders a page once the config has loaded, so this is never null in page markup.</summary>
    protected FirewallConfig Config => State.Config!;

    protected IReadOnlyList<ValidationIssue> Issues { get; set; } = [];

    protected override void OnInitialized() => State.Changed += OnStateChanged;

    private void OnStateChanged() => _ = InvokeAsync(StateHasChanged);

    /// <summary>Saves a change and keeps any problems for the page to show. True when it went live.</summary>
    protected async Task<bool> SaveAsync(Action<FirewallConfig> change)
    {
        Issues = await State.SaveAsync(change);
        return Issues.Count == 0;
    }

    public virtual void Dispose()
    {
        State.Changed -= OnStateChanged;
        GC.SuppressFinalize(this);
    }
}
