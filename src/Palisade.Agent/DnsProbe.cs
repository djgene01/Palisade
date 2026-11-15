using System.Net;
using System.Net.Sockets;

namespace Palisade.Agent;

/// <summary>Asks a name server one question and reports whether anything came back.</summary>
public static class DnsProbe
{
    /// <summary>
    /// Any reply counts, including "no such name": the question is one the server answers by itself,
    /// so this proves the server is up without depending on the internet.
    /// </summary>
    public static async Task<bool> AnswersAsync(string address, int port, string name, TimeSpan patience, CancellationToken ct)
    {
        var query = BuildQuery(name);
        var deadline = DateTimeOffset.UtcNow + patience;
        // A server that was just restarted needs a moment before it listens, so keep asking until the deadline.
        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                using var udp = new UdpClient(AddressFamily.InterNetwork);
                udp.Connect(IPAddress.Parse(address), port);
                await udp.SendAsync(query, ct);
                using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
                wait.CancelAfter(TimeSpan.FromMilliseconds(700));
                var reply = await udp.ReceiveAsync(wait.Token);
                if (reply.Buffer.Length >= 12 && reply.Buffer[0] == query[0] && reply.Buffer[1] == query[1]) return true;
            }
            catch (SocketException)
            {
                // Nothing is listening yet: the kernel refused the packet straight away.
                await Task.Delay(300, ct);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
            }
        }
        return false;
    }

    private static byte[] BuildQuery(string name)
    {
        var bytes = new List<byte> { 0x50, 0x41, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in name.Split('.'))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        bytes.AddRange([0, 0, 1, 0, 1]);
        return [.. bytes];
    }
}
