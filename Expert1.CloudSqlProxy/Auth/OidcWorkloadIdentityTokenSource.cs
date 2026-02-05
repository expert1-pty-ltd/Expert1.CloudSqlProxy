using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Expert1.CloudSqlProxy.Auth;

/// <summary>
/// Provides Google Cloud access tokens by exchanging an OIDC
/// identity token via Workload Identity Federation.
/// </summary>
/// <remarks>
/// This token source performs a token exchange against Google STS using a
/// OIDC-issued JWT and can optionally impersonate a Google service account.
/// Returned access tokens are cached and refreshed automatically as they near
/// expiration.
/// </remarks>
public sealed class OidcWorkloadIdentityTokenSource : IAccessTokenSource, IDisposable
{
    private readonly Func<CancellationToken, ValueTask<string>> _getOidcIdToken;
    private readonly string _audience;
    private readonly string? _serviceAccountEmail;
    private readonly TimeSpan _refreshSkew;

    private readonly HttpClient _http;
    private readonly bool _disposeHttp;

    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private AccessToken _current = new("", DateTimeOffset.MinValue);

    /// <summary>
    /// Initializes a new instance of the <see cref="OidcWorkloadIdentityTokenSource"/> class.
    /// </summary>
    /// <param name="getOidcIdToken">
    /// A callback that returns an OIDC ID token (JWT) for Workload Identity Federation.
    /// </param>
    /// <param name="audience">
    /// The Workload Identity Federation audience identifying the Google identity provider.
    /// </param>
    /// <param name="serviceAccountEmail">
    /// An optional service account email to impersonate when generating access tokens.
    /// </param>
    /// <param name="refreshSkew">
    /// An optional time window used to proactively refresh tokens before they expire.
    /// </param>
    /// <param name="httpClient">
    /// An optional <see cref="HttpClient"/> used for token exchange requests.
    /// If not provided, an internal client is created.
    /// </param>
    public OidcWorkloadIdentityTokenSource(
        Func<CancellationToken, ValueTask<string>> getOidcIdToken,
        string audience,
        string? serviceAccountEmail = null,
        TimeSpan? refreshSkew = null,
        HttpClient? httpClient = null)
    {
        _getOidcIdToken = getOidcIdToken ?? throw new ArgumentNullException(nameof(getOidcIdToken));
        _audience = audience ?? throw new ArgumentNullException(nameof(audience));
        _serviceAccountEmail = serviceAccountEmail;
        _refreshSkew = refreshSkew ?? TimeSpan.FromMinutes(5);

        _http = httpClient ?? new HttpClient();
        _disposeHttp = httpClient is null;
    }

    /// <summary>
    /// Releases resources used by this token source.
    /// </summary>
    public void Dispose()
    {
        _refreshGate.Dispose();
        if (_disposeHttp) _http.Dispose();
    }

    /// <summary>
    /// Returns a valid Google Cloud access token.
    /// </summary>
    /// <remarks>
    /// Tokens are cached and refreshed automatically. Concurrent callers
    /// will coordinate so that only one refresh occurs at a time.
    /// </remarks>
    /// <param name="cancellationToken">
    /// A token used to cancel the token acquisition operation.
    /// </param>
    /// <returns>
    /// A valid <see cref="AccessToken"/> for use with Google APIs.
    /// </returns>
    public async ValueTask<AccessToken> GetTokenAsync(CancellationToken cancellationToken)
    {
        AccessToken cached = Volatile.Read(ref _current);
        if (!cached.IsExpired(_refreshSkew))
            return cached;

        await _refreshGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            cached = Volatile.Read(ref _current);
            if (!cached.IsExpired(_refreshSkew))
                return cached;

            AccessToken refreshed = await RefreshAsync(cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref _current, refreshed);
            return refreshed;
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    private async Task<AccessToken> RefreshAsync(CancellationToken ct)
    {
        // 1) Get ODIC JWT
        string OidcJwt = await _getOidcIdToken(ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(OidcJwt))
            throw new InvalidOperationException("OIDC token provider returned an empty token.");

        // 2) STS exchange
        (string AccessToken, int ExpiresInSeconds) sts = await ExchangeWithStsAsync(OidcJwt, ct).ConfigureAwait(false);

        // 3) Optional service account impersonation
        if (!string.IsNullOrEmpty(_serviceAccountEmail))
        {
            (string AccessToken, DateTimeOffset ExpiresAt) sa = await ImpersonateServiceAccountAsync(sts.AccessToken, _serviceAccountEmail!, ct)
                .ConfigureAwait(false);

            return new AccessToken(sa.AccessToken, sa.ExpiresAt);
        }

        // STS provides expires_in seconds
        return new AccessToken(sts.AccessToken, DateTimeOffset.UtcNow.AddSeconds(sts.ExpiresInSeconds));
    }

    private async Task<(string AccessToken, int ExpiresInSeconds)> ExchangeWithStsAsync(string subjectJwt, CancellationToken ct)
    {
        Dictionary<string, string> form = new()
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["requested_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
            ["subject_token"] = subjectJwt,
            ["audience"] = _audience,
            // Scope is optional depending on your pool/provider setup, but typically you want cloud-platform:
            ["scope"] = "https://www.googleapis.com/auth/cloud-platform",
        };

        using HttpResponseMessage resp = await _http.PostAsync(
            "https://sts.googleapis.com/v1/token",
            new FormUrlEncodedContent(form),
            ct).ConfigureAwait(false);

        string body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException($"STS token exchange failed ({(int)resp.StatusCode}): {body}");

        using JsonDocument doc = JsonDocument.Parse(body);
        string accessToken = doc.RootElement.GetProperty("access_token").GetString()!;
        int expiresIn = doc.RootElement.GetProperty("expires_in").GetInt32();
        return (accessToken, expiresIn);
    }

    private async Task<(string AccessToken, DateTimeOffset ExpiresAt)> ImpersonateServiceAccountAsync(
        string stsAccessToken,
        string serviceAccountEmail,
        CancellationToken ct)
    {
        string url =
            $"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{serviceAccountEmail}:generateAccessToken";

        using HttpRequestMessage req = new(HttpMethod.Post, url);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", stsAccessToken);

        var payload = new
        {
            scope = new[] { "https://www.googleapis.com/auth/cloud-platform" },
            // lifetime optional; omit to use default
        };

        req.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

        using HttpResponseMessage resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        string body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException($"Impersonation failed ({(int)resp.StatusCode}): {body}");

        using JsonDocument doc = JsonDocument.Parse(body);
        string accessToken = doc.RootElement.GetProperty("accessToken").GetString()!;
        DateTimeOffset expireTime = doc.RootElement.GetProperty("expireTime").GetDateTimeOffset(); // RFC3339 timestamp
        return (accessToken, expireTime);
    }
}
