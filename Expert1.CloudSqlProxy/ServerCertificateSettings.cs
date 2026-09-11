using Google.Apis.SQLAdmin.v1beta4.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
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
        private readonly byte[][] certificateData;

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

            certificateData = ParseCertificateData(connectSettings.ServerCaCert.Cert.AsSpan());

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

        private static byte[][] ParseCertificateData(ReadOnlySpan<char> pem)
        {
            List<byte[]> certificates = new();
            while (PemEncoding.TryFind(pem, out PemFields fields))
            {
                if (pem[fields.Label].SequenceEqual("CERTIFICATE".AsSpan()))
                {
                    // Dispose each parsed certificate even if a later PEM entry fails.
                    using X509Certificate2 certificate = X509Certificate2.CreateFromPem(pem[fields.Location]);
                    certificates.Add(certificate.RawData);
                }

                pem = pem[fields.Location.End..];
            }

            if (certificates.Count == 0)
                throw new CryptographicException("Cloud SQL did not provide a server CA certificate.");

            return certificates.ToArray();
        }

        // The caller owns all copies and must dispose the bundle after TLS authentication.
        public CertificateBundle CreateCertificates()
        {
            CertificateBundle bundle = new();
            try
            {
                foreach (byte[] data in certificateData)
                {
#if NET9_0_OR_GREATER
                    bundle.Certificates.Add(X509CertificateLoader.LoadCertificate(data));
#else
                    bundle.Certificates.Add(new X509Certificate2(data));
#endif
                }

                return bundle;
            }
            catch
            {
                bundle.Dispose();
                throw;
            }
        }

        internal sealed class CertificateBundle : IDisposable
        {
            public X509Certificate2Collection Certificates { get; } = new();

            public void Dispose()
            {
                foreach (X509Certificate2 certificate in Certificates)
                    certificate.Dispose();

                Certificates.Clear();
            }
        }
    }
}
