using Expert1.CloudSqlProxy.Auth;
using Google.Apis.Auth.OAuth2;
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
    private readonly object identityReference;
    private readonly int hashCode;

    private ProxyCacheKey(
        string instance,
        AuthMode authMode,
        AuthenticationMethod credentialAuthenticationMethod,
        string credentialFingerprint,
        object identityReference)
    {
        Instance = Utilities.NormalizeInstanceName(instance);
        this.authMode = authMode;
        this.credentialAuthenticationMethod = credentialAuthenticationMethod;
        this.credentialFingerprint = credentialFingerprint;
        this.identityReference = identityReference;

        int authIdentityHashCode = UsesReferenceIdentity(authMode)
            ? RuntimeHelpers.GetHashCode(identityReference)
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
        string credentialJson)
    {
        ArgumentNullException.ThrowIfNull(credentialJson);

        return new ProxyCacheKey(
            instance,
            AuthMode.GoogleCredential,
            authenticationMethod,
            CreateCredentialFingerprint(credentialJson),
            identityReference: null);
    }

    public static ProxyCacheKey ForGoogleCredential(
        string instance,
        GoogleCredential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);

        return new ProxyCacheKey(
            instance,
            AuthMode.SuppliedGoogleCredential,
            credentialAuthenticationMethod: default,
            credentialFingerprint: string.Empty,
            identityReference: credential);
    }

    public static ProxyCacheKey ForAccessTokenSource(
        string instance,
        IAccessTokenSource accessTokenSource)
    {
        ArgumentNullException.ThrowIfNull(accessTokenSource);

        return new ProxyCacheKey(
            instance,
            AuthMode.AccessTokenSource,
            credentialAuthenticationMethod: default,
            credentialFingerprint: string.Empty,
            identityReference: accessTokenSource);
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

        if (UsesReferenceIdentity(authMode))
            return ReferenceEquals(identityReference, other.identityReference);

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

    private static bool UsesReferenceIdentity(AuthMode authMode)
        => authMode is AuthMode.AccessTokenSource or AuthMode.SuppliedGoogleCredential;
}
