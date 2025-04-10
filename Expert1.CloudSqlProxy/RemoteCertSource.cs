using Google;
using Google.Apis.SQLAdmin.v1beta4;
using Google.Apis.SQLAdmin.v1beta4.Data;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Expert1.CloudSqlProxy
{
    /// <summary>
    /// Manages the retrieval and caching of certificates required for establishing
    /// secure connections to Google Cloud SQL instances. Handles RSA key generation,
    /// and fetching ephemeral certificates from the Cloud SQL Admin API.
    /// </summary>
    internal sealed class RemoteCertSource
    {
#if NET9_0_OR_GREATER
        private readonly Lock keyLock = new();
#else
        private readonly object keyLock = new();
#endif
        private readonly SemaphoreSlim certLock = new(1, 1);
        private readonly SQLAdminService service;
        private RSA privateKey;
        private X509Certificate2 clientCert;
        private static readonly TimeSpan refreshWindow = TimeSpan.FromMinutes(15);
        private static readonly TimeSpan baseBackoff = TimeSpan.FromMilliseconds(200);
        private readonly CancellationTokenSource refreshCts;
        private readonly Task refreshTask;
        private readonly string project;
        private readonly string regionName;
        private string publicKeyPem;
        
        public RemoteCertSource(SQLAdminService service, string instance)
        {
            this.service = service;
            (project, string region, string name) = Utilities.SplitName(instance);
            regionName = $"{region}~{name}";
            refreshCts = new();
            refreshTask = Task.Run(() => BackgroundRefreshLoop(refreshCts.Token));
        }

        private RSA GenerateKey()
        {
            lock (keyLock)
            {
                if (privateKey == null)
                {
                    privateKey = RSA.Create();
                    privateKey.KeySize = 2048;
                    publicKeyPem = privateKey.ExportSubjectPublicKeyInfoPem();
                }
                
                return privateKey;
            }
        }

        private async Task BackgroundRefreshLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromMinutes(50), token);
                    await GetValidClientCertificateAsync(); // Will refresh if needed
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        public void StopBackgroundRefresh()
        {
            refreshCts?.Cancel();
            refreshTask?.Wait();
            refreshCts?.Dispose();
        }

        public async Task<X509Certificate2> GetValidClientCertificateAsync()
        {
            await certLock.WaitAsync();
            try
            {
                if (clientCert != null && clientCert.NotAfter > DateTime.UtcNow.Add(refreshWindow))
                {
                    return clientCert;
                }

                RSA key = GenerateKey();                
                GenerateEphemeralCertRequest generateCertRequest = new()
                {
                    PublicKey = publicKeyPem
                };

                ConnectResource.GenerateEphemeralCertRequest request = service.Connect.GenerateEphemeralCert(generateCertRequest, project, regionName);
                GenerateEphemeralCertResponse response = await RetryWithBackoffAsync(() => request.ExecuteAsync());
                using X509Certificate2 certificate = X509Certificate2.CreateFromPem(response.EphemeralCert.Cert.AsSpan());
                X509Certificate2 certWithKey = certificate.CopyWithPrivateKey(key);
                byte[] pfxData = certWithKey.Export(X509ContentType.Pkcs12);
#if NET9_0_OR_GREATER
                clientCert =  X509CertificateLoader.LoadPkcs12(pfxData, password: null);
#else
                clientCert = new X509Certificate2(pfxData);
#endif
                return clientCert;
            }
            finally
            {
                certLock.Release();
            }
        }

        private static async Task<T> RetryWithBackoffAsync<T>(Func<Task<T>> action, int retries = 5)
        {
            
            double backoffMultiplier = 1.618;

            for (int i = 0; i < retries; i++)
            {
                try
                {
                    return await action();
                }
                catch (Exception ex) when (IsRetryableException(ex))
                {
                    TimeSpan backoff = TimeSpan.FromMilliseconds(baseBackoff.TotalMilliseconds * Math.Pow(backoffMultiplier, i + 1));
                    await Task.Delay(backoff);
                }
            }
            return await action();
        }

        private static bool IsRetryableException(Exception ex)
            => ex is GoogleApiException gex && (int)gex.HttpStatusCode >= 500;
    }
}
