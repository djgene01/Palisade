using Palisade.App.Services;

namespace Palisade.App;

public partial class App : Application
{
    private readonly AppLock _lock;

    public App(AppLock appLock)
    {
        _lock = appLock;
        InitializeComponent();
    }

    protected override Window CreateWindow(IActivationState? activationState)
    {
        var window = new Window(new MainPage()) { Title = "Palisade" };
        // Away for more than a minute, the app locks again when the owner comes back (if the lock is on).
        window.Stopped += (_, _) => _lock.Left();
        window.Resumed += (_, _) => _lock.Returned();
        return window;
    }
}
