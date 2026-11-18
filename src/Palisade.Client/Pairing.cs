using System.Net.Http.Json;
using Palisade.Core;

namespace Palisade.Client;

/// <summary>Linking this device to a firewall with the one-time code from the firewall's Advanced page.</summary>
public static class Pairing
{
    /// <summary>
    /// Trades the code for this device's own token. <paramref name="pin"/> is the key the firewall must present:
    /// from the scanned code, or the one the person confirmed by comparing fingerprints. If the firewall shows any
    /// other key, the code is never sent, so a look-alike on the network learns nothing it could use.
    /// </summary>
    public static async Task<FirewallLink> PairAsync(FirewallAddress address, string pin, string code, string deviceName, CancellationToken ct = default)
    {
        if (!CertificatePin.IsValid(pin)) throw new FirewallException("The firewall's fingerprint is missing or damaged. Scan the code again.");
        using var http = PinnedConnection.Client(address, pin);
        HttpResponseMessage response;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(20));
            // Over the pinned connection first: is this a firewall this app can work with at all?
            var info = await http.GetFromJsonAsync<ApiInfo>($"{AppContract.Prefix}/info", PinnedConnection.Json, timeout.Token);
            PinnedConnection.CheckCompatible(info);
            response = await http.PostAsJsonAsync($"{AppContract.Prefix}/pair", new PairRequest(code, deviceName), PinnedConnection.Json, timeout.Token);
        }
        catch (HttpRequestException ex) when (ex.HttpRequestError == HttpRequestError.SecureConnectionError)
        {
            throw new FirewallException("The device at that address is not the firewall in the code: its fingerprint is different. Nothing was sent to it.", ex);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new FirewallException($"The firewall at {address.Host} did not answer. Check that this device is on your home network.", ex);
        }
        using (response)
        {
            if (response.StatusCode == System.Net.HttpStatusCode.BadRequest)
                throw new FirewallException((await response.Content.ReadFromJsonAsync<ApiProblem>(PinnedConnection.Json, ct))?.Problem
                    ?? "The firewall did not accept that code.");
            await PinnedConnection.EnsureOkAsync(response, ct);
            var paired = await response.Content.ReadFromJsonAsync<PairResponse>(PinnedConnection.Json, ct)
                ?? throw new FirewallException("The firewall's answer could not be read.");
            return new FirewallLink(address.Host, address.Port, pin, paired.Token, paired.DeviceId);
        }
    }

    /// <summary>Pairs from a scanned code, whose key is already known.</summary>
    public static Task<FirewallLink> PairAsync(PairingInvite invite, string deviceName, CancellationToken ct = default) =>
        PairAsync(invite.Address, invite.Address.Pin!, invite.Code, deviceName, ct);
}
