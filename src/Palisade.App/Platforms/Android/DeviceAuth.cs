using AndroidX.Biometric;
using AndroidX.Core.Content;
using AndroidX.Fragment.App;

namespace Palisade.App.Services;

public static partial class DeviceAuth
{
    // A fingerprint or face, or the screen lock itself, so a phone without biometrics can use the lock too.
    private const int Allowed = BiometricManager.Authenticators.BiometricWeak | BiometricManager.Authenticators.DeviceCredential;

    public static partial Task<bool> IsAvailableAsync() =>
        Task.FromResult(BiometricManager.From(Platform.AppContext).CanAuthenticate(Allowed) == BiometricManager.BiometricSuccess);

    public static partial Task<bool> VerifyAsync(string reason) => MainThread.InvokeOnMainThreadAsync(() =>
    {
        if (Platform.CurrentActivity is not FragmentActivity activity || ContextCompat.GetMainExecutor(activity) is not { } executor)
            return Task.FromResult(false);
        var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var prompt = new BiometricPrompt(activity, executor, new Callback(done));
        var info = new BiometricPrompt.PromptInfo.Builder()
            .SetTitle("Palisade")
            .SetSubtitle(reason)
            .SetAllowedAuthenticators(Allowed)
            .Build();
        prompt.Authenticate(info);
        return done.Task;
    });

    private sealed class Callback(TaskCompletionSource<bool> done) : BiometricPrompt.AuthenticationCallback
    {
        public override void OnAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) => done.TrySetResult(true);

        // Cancelled, too many tries, or no way to check: the app stays locked and offers to try again.
        public override void OnAuthenticationError(int errorCode, Java.Lang.ICharSequence errString) => done.TrySetResult(false);

        // A finger that did not match: the prompt itself lets the owner try again, so nothing ends here.
        public override void OnAuthenticationFailed() { }
    }
}
