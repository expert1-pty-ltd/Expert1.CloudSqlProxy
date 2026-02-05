using System;

namespace Expert1.CloudSqlProxy.Auth;

/// <summary>
/// Represents an OAuth2 bearer access token and its expiration time.
/// </summary>
public record AccessToken(
    string Token,
    DateTimeOffset ExpiresAt)
{
    /// <summary>
    /// Determines whether the access token is expired or about to expire.
    /// </summary>
    /// <param name="skew">
    /// An optional time window to treat the token as expired before its actual
    /// expiration time (for example, to allow for clock skew or proactive refresh).
    /// </param>
    /// <returns>
    /// <c>true</c> if the current time is greater than or equal to the expiration
    /// time minus the specified skew; otherwise, <c>false</c>.
    /// </returns>
    public bool IsExpired(TimeSpan? skew = null)
    {
        if (ExpiresAt <= DateTimeOffset.UnixEpoch)
            return true;

        TimeSpan s = skew ?? TimeSpan.Zero;
        return DateTimeOffset.UtcNow >= ExpiresAt - s;
    }
}
