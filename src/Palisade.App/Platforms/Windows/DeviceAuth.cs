using Windows.Security.Credentials.UI;

namespace Palisade.App.Services;

public static partial class DeviceAuth
{
    public static partial async Task<bool> IsAvailableAsync() =>
        await UserConsentVerifier.CheckAvailabilityAsync() == UserConsentVerifierAvailability.Available;

    public static partial async Task<bool> VerifyAsync(string reason)
    {
        // Tied to the app's window, so Windows Hello opens in front of it rather than somewhere behind.
        if (Application.Current?.Windows.FirstOrDefault()?.Handler?.PlatformView is not Microsoft.UI.Xaml.Window window) return false;
        var handle = WinRT.Interop.WindowNative.GetWindowHandle(window);
        var result = await UserConsentVerifierInterop.RequestVerificationForWindowAsync(handle, reason);
        return result == UserConsentVerificationResult.Verified;
    }
}
