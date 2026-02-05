using System.Threading;
using System.Threading.Tasks;

namespace Expert1.CloudSqlProxy.Auth
{
    /// <summary>
    /// An <see cref="IAccessTokenSource"/> whose access token can be updated externally.
    /// </summary>
    public sealed class SwappableTokenSource : IAccessTokenSource
    {
        private AccessToken _current;

        /// <summary>
        /// Initializes the token source with an initial access token.
        /// </summary>
        public SwappableTokenSource(AccessToken initial) => _current = initial;

        /// <summary>
        /// Replaces the current access token.
        /// </summary>
        public void Update(AccessToken next) => Volatile.Write(ref _current, next);

        /// <inheritdoc />
        public ValueTask<AccessToken> GetTokenAsync(CancellationToken ct)
            => ValueTask.FromResult(Volatile.Read(ref _current));
    }

}
