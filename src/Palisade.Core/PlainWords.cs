namespace Palisade.Core;

/// <summary>
/// An error whose message is already written for the owner, such as "Can't reach the firewall at 192.168.50.1.
/// Are you on your home network?". Screens show it as it is, instead of wrapping it in a general explanation.
/// </summary>
public class PlainWordsException(string message, Exception? inner = null) : Exception(message, inner);

public static class Problem
{
    /// <summary>
    /// The sentence to show for a failed call. A plain-words error speaks for itself (with "Nothing was changed."
    /// added after a failed save); anything else gets the screen's general explanation with the detail in brackets.
    /// </summary>
    public static string Explain(Exception ex, string general, bool nothingChanged = false) =>
        ex is PlainWordsException
            ? nothingChanged ? $"{ex.Message} Nothing was changed." : ex.Message
            : $"{general} ({ex.Message})";
}
