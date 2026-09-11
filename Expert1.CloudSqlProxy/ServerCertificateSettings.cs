using Google.Apis.SQLAdmin.v1beta4.Data;
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Expert1.CloudSqlProxy
{
    /// <summary>
    /// An immutable snapshot of the CA, server identity, and address returned by the Admin API.
    /// Stores public certificate bytes so refreshing the cache cannot invalidate an
    /// in-flight handshake's certificate.
    /// </summary>
    internal sealed class ServerCertificateSettings
    {
        private readonly byte[] certificateData;

        public string TargetHost { get; }
        public bool RequireHostnameValidation { get; }
        public string ServerIp { get; }

        public ServerCertificateSettings(ConnectSettings connectSettings, string project, string instanceId)
        {
            // The Admin API defines an unspecified CA mode as the per-instance CA.
            if (string.IsNullOrWhiteSpace(connectSettings.ServerCaMode) ||
                string.Equals(connectSettings.ServerCaMode, "CA_MODE_UNSPECIFIED", StringComparison.Ordinal) ||
                string.Equals(connectSettings.ServerCaMode, "GOOGLE_MANAGED_INTERNAL_CA", StringComparison.Ordinal))
            {
                // The per-instance CA also establishes server identity.
                TargetHost = $"{project}:{instanceId}";
                RequireHostnameValidation = false;
            }
            else if (string.Equals(connectSettings.ServerCaMode, "GOOGLE_MANAGED_CAS_CA", StringComparison.Ordinal) ||
                string.Equals(connectSettings.ServerCaMode, "CUSTOMER_MANAGED_CAS_CA", StringComparison.Ordinal))
            {
                if (string.IsNullOrWhiteSpace(connectSettings.DnsName))
                {
                    throw new InvalidOperationException(
                        $"Cloud SQL did not provide a DNS name for server identity validation " +
                        $"with CA mode '{connectSettings.ServerCaMode}'.");
                }

                // These CAs can sign certificates for multiple servers, so the DNS
                // name must also match the certificate SAN.
                TargetHost = connectSettings.DnsName;
                RequireHostnameValidation = true;
            }
            else
            {
                throw new InvalidOperationException(
                    $"Unsupported Cloud SQL server CA mode '{connectSettings.ServerCaMode}'.");
            }

            using X509Certificate2 certificate =
                X509Certificate2.CreateFromPem(connectSettings.ServerCaCert.Cert.AsSpan());
            certificateData = certificate.RawData;

            // Capture the startup address from the same response as the TLS settings.
            ServerIp =
                connectSettings.IpAddresses?
                    .FirstOrDefault(x => string.Equals(x?.Type, "PRIMARY", StringComparison.OrdinalIgnoreCase))
                    ?.IpAddress
                ?? connectSettings.IpAddresses?
                    .FirstOrDefault(x => string.Equals(x?.Type, "PRIVATE", StringComparison.OrdinalIgnoreCase))
                    ?.IpAddress
                ?? connectSettings.IpAddresses?
                    .FirstOrDefault()
                    ?.IpAddress;
        }

        // The caller owns this copy and must dispose it after TLS authentication.
        public X509Certificate2 CreateCertificate()
        {
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadCertificate(certificateData);
#else
            return new X509Certificate2(certificateData);
#endif
        }
    }
}
