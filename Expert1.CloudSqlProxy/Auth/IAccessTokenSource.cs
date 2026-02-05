using System.Threading;
using System.Threading.Tasks;

namespace Expert1.CloudSqlProxy.Auth
{
    /// <summary>
    /// Provides OAuth2 access tokens for outbound Google API requests.
    /// Implementations must return a valid access token and its expiry.
    /// </summary>
    public interface IAccessTokenSource
    {
        /// <summary>
        /// Returns a valid Google API access token. Implementations may cache and refresh
        /// tokens internally and must be safe for concurrent callers.
        /// </summary>
        ValueTask<AccessToken> GetTokenAsync(CancellationToken cancellationToken);
    }
}
