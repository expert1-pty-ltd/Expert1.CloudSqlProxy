using Expert1.CloudSqlProxy.Auth;
using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Expert1.CloudSqlProxy;

internal sealed class ProxyCacheKey : IEquatable<ProxyCacheKey>
{
    private static readonly StringComparer InstanceComparer = StringComparer.OrdinalIgnoreCase;

    private readonly AuthMode authMode;
    private readonly AuthenticationMethod credentialAuthenticationMethod;
    private readonly string credentialFingerprint;
    private readonly IAccessTokenSource accessTokenSource;
    private readonly int hashCode;

    private ProxyCacheKey(
        string instance,
        AuthMode authMode,
        AuthenticationMethod credentialAuthenticationMethod,
        string credentialFingerprint,
        IAccessTokenSource accessTokenSource)
    {
        Instance = Utilities.NormalizeInstanceName(instance);
        this.authMode = authMode;
        this.credentialAuthenticationMethod = credentialAuthenticationMethod;
        this.credentialFingerprint = credentialFingerprint;
        this.accessTokenSource = accessTokenSource;

        int authIdentityHashCode = authMode == AuthMode.AccessTokenSource
            ? RuntimeHelpers.GetHashCode(accessTokenSource)
            : HashCode.Combine(credentialAuthenticationMethod, StringComparer.Ordinal.GetHashCode(credentialFingerprint));

        hashCode = HashCode.Combine(
            InstanceComparer.GetHashCode(Instance),
            authMode,
            authIdentityHashCode);
    }

    public string Instance { get; }

    public static ProxyCacheKey ForGoogleCredential(
        AuthenticationMethod authenticationMethod,
        string instance,
        string credentials)
    {
        if (credentials is null)
            throw new ArgumentNullException(nameof(credentials));

        return new ProxyCacheKey(
            instance,
            AuthMode.GoogleCredential,
            authenticationMethod,
            CreateCredentialFingerprint(credentials),
            accessTokenSource: null);
    }

    public static ProxyCacheKey ForAccessTokenSource(
        string instance,
        IAccessTokenSource accessTokenSource)
    {
        if (accessTokenSource is null)
            throw new ArgumentNullException(nameof(accessTokenSource));

        return new ProxyCacheKey(
            instance,
            AuthMode.AccessTokenSource,
            credentialAuthenticationMethod: default,
            credentialFingerprint: string.Empty,
            accessTokenSource);
    }

    public bool Equals(ProxyCacheKey other)
    {
        if (ReferenceEquals(this, other))
            return true;

        if (other is null ||
            authMode != other.authMode ||
            !InstanceComparer.Equals(Instance, other.Instance))
        {
            return false;
        }

        if (authMode == AuthMode.AccessTokenSource)
            return ReferenceEquals(accessTokenSource, other.accessTokenSource);

        return credentialAuthenticationMethod == other.credentialAuthenticationMethod &&
            StringComparer.Ordinal.Equals(credentialFingerprint, other.credentialFingerprint);
    }

    public override bool Equals(object obj)
        => obj is ProxyCacheKey other && Equals(other);

    public override int GetHashCode() => hashCode;

    private static string CreateCredentialFingerprint(string credentials)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(credentials));
        return Convert.ToHexString(hash);
    }
}
