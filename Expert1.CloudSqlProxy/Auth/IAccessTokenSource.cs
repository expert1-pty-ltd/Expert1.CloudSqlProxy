using System.Threading;
using System.Threading.Tasks;

namespace Expert1.CloudSqlProxy.Auth
{
    /// <summary>
    /// Provides OAuth2 access tokens for outbound Google API requests.
    /// Implementations must return a valid access token and its expiry.
    /// </summary>
    /// <remarks>
    /// A token source instance represents one authentication identity for proxy
    /// reuse. Reuse the same instance for refreshed tokens belonging to the same
    /// user, tenant, or service identity. Create a separate token source instance
    /// for each distinct identity, especially in user pass-through scenarios.
    /// </remarks>
    public interface IAccessTokenSource
    {
        /// <summary>
        /// Returns a valid Google API access token. Implementations may cache and refresh
        /// tokens internally and must be safe for concurrent callers.
        /// </summary>
        ValueTask<AccessToken> GetTokenAsync(CancellationToken cancellationToken);
    }
}
