using Google.Apis.Http;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Expert1.CloudSqlProxy.Auth;

internal sealed class AccessTokenInterceptor : IHttpExecuteInterceptor
{
    private readonly IAccessTokenSource _source;

    public AccessTokenInterceptor(IAccessTokenSource source) => _source = source;

    public async Task InterceptAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        AccessToken token = await _source.GetTokenAsync(cancellationToken).ConfigureAwait(false);

        // Optional: skip if already set by caller
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
    }
}
