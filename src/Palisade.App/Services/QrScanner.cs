using Palisade.Core;
using ZXing.Net.Maui;
using ZXing.Net.Maui.Controls;

namespace Palisade.App.Services;

/// <summary>Opens the camera over the app and waits for one QR code, or for the person to cancel.</summary>
public sealed class QrScanner
{
    /// <summary>The text in the first QR code seen, or null when cancelled.</summary>
    public async Task<string?> ScanAsync()
    {
        var permission = await MainThread.InvokeOnMainThreadAsync(() => Permissions.RequestAsync<Permissions.Camera>());
        if (permission != PermissionStatus.Granted)
            throw new PlainWordsException("Palisade needs the camera to read the code. You can type the address and code instead.");

        var page = new ScanPage();
        var navigation = Application.Current!.Windows[0].Page!.Navigation;
        await MainThread.InvokeOnMainThreadAsync(() => navigation.PushModalAsync(page));
        var text = await page.Result;
        await MainThread.InvokeOnMainThreadAsync(async () =>
        {
            // The back button may already have closed it.
            if (navigation.ModalStack.Contains(page)) await navigation.PopModalAsync();
        });
        return text;
    }

    private sealed class ScanPage : ContentPage
    {
        private readonly TaskCompletionSource<string?> _result = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly CameraBarcodeReaderView _camera;

        public Task<string?> Result => _result.Task;

        public ScanPage()
        {
            BackgroundColor = Colors.Black;
            _camera = new CameraBarcodeReaderView
            {
                Options = new BarcodeReaderOptions { Formats = BarcodeFormat.QrCode, AutoRotate = true, Multiple = false },
            };
            _camera.BarcodesDetected += (_, e) =>
            {
                if (e.Results.FirstOrDefault()?.Value is { Length: > 0 } value) _result.TrySetResult(value);
            };

            var cancel = new Button { Text = "Cancel", Margin = new Thickness(0, 12, 0, 0) };
            cancel.Clicked += (_, _) => _result.TrySetResult(null);
            SemanticProperties.SetHint(cancel, "Closes the camera without linking");

            Content = new Grid
            {
                RowDefinitions = [new RowDefinition(GridLength.Star), new RowDefinition(GridLength.Auto)],
                Children =
                {
                    _camera,
                    new VerticalStackLayout
                    {
                        Padding = new Thickness(20, 16, 20, 28),
                        BackgroundColor = Color.FromArgb("#0e1a33"),
                        Children =
                        {
                            new Label
                            {
                                Text = "Point the camera at the code on the firewall's page: Advanced, then Phones and tablets.",
                                TextColor = Colors.White, FontSize = 17, HorizontalTextAlignment = TextAlignment.Center,
                            },
                            cancel,
                        },
                    }.Row(1),
                },
            };
        }

        protected override void OnDisappearing()
        {
            _camera.IsDetecting = false;
            _result.TrySetResult(null);
            base.OnDisappearing();
        }
    }
}

internal static class GridRows
{
    public static T Row<T>(this T view, int row) where T : BindableObject
    {
        Grid.SetRow(view, row);
        return view;
    }
}
