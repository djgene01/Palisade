namespace Palisade.App.Services;

/// <summary>
/// Asks for the phone's fingerprint, face or screen lock before the app shows anything, when the owner has
/// switched that on. It locks when the app starts and when it comes back after a minute away. It guards the
/// screens; the links themselves are already kept in the phone's secure storage.
/// </summary>
public sealed class AppLock
{
    private const string EnabledKey = "palisade.lock";
    public static readonly TimeSpan Grace = TimeSpan.FromMinutes(1);

    private readonly TimeProvider _clock;
    private DateTimeOffset? _leftAt;

    public AppLock(TimeProvider clock)
    {
        _clock = clock;
        Locked = Enabled;
    }

    public bool Enabled
    {
        get => Preferences.Default.Get(EnabledKey, false);
        private set => Preferences.Default.Set(EnabledKey, value);
    }

    public bool Locked { get; private set; }

    /// <summary>Raised when the app locks or unlocks, so the screens can redraw.</summary>
    public event Action? Changed;

    /// <summary>Called when the app goes to the background.</summary>
    public void Left() => _leftAt = _clock.GetUtcNow();

    /// <summary>Called when the app comes back. A short look at another app does not lock it.</summary>
    public void Returned()
    {
        if (Enabled && _leftAt is { } left && _clock.GetUtcNow() - left >= Grace && !Locked)
        {
            Locked = true;
            Changed?.Invoke();
        }
        _leftAt = null;
    }

    public Task<bool> IsAvailableAsync() => DeviceAuth.IsAvailableAsync();

    /// <summary>Asks the phone to confirm it is the owner. True when it did.</summary>
    public async Task<bool> UnlockAsync()
    {
        if (!Locked) return true;
        if (!await DeviceAuth.VerifyAsync("Confirm it's you to open Palisade")) return false;
        Locked = false;
        Changed?.Invoke();
        return true;
    }

    /// <summary>
    /// Switches the lock on, after one successful check, so nobody turns on a lock they cannot open.
    /// Returns a reason in plain words when it could not be switched on.
    /// </summary>
    public async Task<string?> TurnOnAsync()
    {
        if (!await DeviceAuth.IsAvailableAsync())
            return OperatingSystem.IsWindows()
                ? "This computer has no Windows Hello (face, fingerprint or PIN) set up. Set it up in Windows Settings, then try again."
                : "This phone has no screen lock set up. Set a PIN, pattern, fingerprint or face unlock in the phone's settings, then try again.";
        if (!await DeviceAuth.VerifyAsync("Confirm it's you to turn on the lock")) return "The lock was not turned on.";
        Enabled = true;
        Changed?.Invoke();
        return null;
    }

    public void TurnOff()
    {
        Enabled = false;
        Locked = false;
        Changed?.Invoke();
    }
}

/// <summary>The phone's own way of confirming the owner: fingerprint, face, or the screen lock PIN or pattern.</summary>
public static partial class DeviceAuth
{
    public static partial Task<bool> IsAvailableAsync();

    /// <summary>Shows the system prompt. True when the owner confirmed; false when cancelled or it failed.</summary>
    public static partial Task<bool> VerifyAsync(string reason);
}
