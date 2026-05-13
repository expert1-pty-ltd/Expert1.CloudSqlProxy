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
    internal sealed class RemoteCertSource : IDisposable
    {
#if NET9_0_OR_GREATER
        private readonly Lock keyLock = new();
#else
        private readonly object keyLock = new();
#endif
        private readonly SemaphoreSlim certRefreshLock = new(1, 1);
        private readonly ReaderWriterLockSlim certCacheLock = new();
        private readonly SQLAdminService service;
        private RSA privateKey;
        private X509Certificate2 clientCert;
        private byte[] clientCertPkcs12;
        private int disposed;
        private int resourcesDisposed;
        private static readonly TimeSpan refreshWindow = TimeSpan.FromMinutes(15);
        private static readonly TimeSpan baseBackoff = TimeSpan.FromMilliseconds(200);
        private static readonly TimeSpan refershLoopTime = TimeSpan.FromMinutes(50);
        private static readonly TimeSpan disposeRefreshWaitTimeout = TimeSpan.FromSeconds(1);
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
                    await Task.Delay(refershLoopTime, token);
                    await GetValidClientCertificateAsync(token); // Will refresh if needed
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
                return;

            refreshCts.Cancel();

            if (WaitForRefreshTask() && TryDisposeResources())
            {
                return;
            }

            _ = DisposeResourcesWhenIdleAsync();
        }

        private bool WaitForRefreshTask()
        {
            try
            {
                return refreshTask.Wait(disposeRefreshWaitTimeout);
            }
            catch (AggregateException)
            {
                return true;
            }
        }

        private bool TryDisposeResources()
        {
            if (!certRefreshLock.Wait(0))
                return false;

            DisposeResourcesWithRefreshLockHeld();
            return true;
        }

        private async Task DisposeResourcesWhenIdleAsync()
        {
            try
            {
                await refreshTask.ConfigureAwait(false);
            }
            catch
            {
                // Observe refresh failures; cleanup still needs to release cached certificate material.
            }

            await certRefreshLock.WaitAsync().ConfigureAwait(false);
            DisposeResourcesWithRefreshLockHeld();
        }

        private void DisposeResourcesWithRefreshLockHeld()
        {
            if (Interlocked.Exchange(ref resourcesDisposed, 1) != 0)
            {
                certRefreshLock.Release();
                return;
            }

            try
            {
                certCacheLock.EnterWriteLock();
                try
                {
                    clientCert?.Dispose();
                    ClearPfxData(clientCertPkcs12);
                    privateKey?.Dispose();
                    clientCert = null;
                    clientCertPkcs12 = null;
                    privateKey = null;
                }
                finally
                {
                    certCacheLock.ExitWriteLock();
                }
            }
            finally
            {
                certRefreshLock.Release();
                certRefreshLock.Dispose();
                certCacheLock.Dispose();
                refreshCts.Dispose();
            }
        }

        public ValueTask<X509Certificate2> GetValidClientCertificateAsync(CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            if (TryGetCachedCertificate(out X509Certificate2 certificate))
                return new ValueTask<X509Certificate2>(certificate);

            return new ValueTask<X509Certificate2>(GetValidClientCertificateSlowAsync(cancellationToken));
        }

        private async Task<X509Certificate2> GetValidClientCertificateSlowAsync(CancellationToken cancellationToken)
        {
            await certRefreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();

                if (TryGetCachedCertificate(out X509Certificate2 certificate))
                    return certificate;

                RSA key = GenerateKey();
                GenerateEphemeralCertRequest generateCertRequest = new()
                {
                    PublicKey = publicKeyPem
                };

                ConnectResource.GenerateEphemeralCertRequest request = service.Connect.GenerateEphemeralCert(generateCertRequest, project, regionName);
                GenerateEphemeralCertResponse response = await RetryWithBackoffAsync(() => request.ExecuteAsync(cancellationToken), cancellationToken: cancellationToken).ConfigureAwait(false);
                using X509Certificate2 certificateFromPem = X509Certificate2.CreateFromPem(response.EphemeralCert.Cert.AsSpan());
                using X509Certificate2 certWithKey = certificateFromPem.CopyWithPrivateKey(key);

                byte[] newPfxData = certWithKey.Export(X509ContentType.Pkcs12);
                X509Certificate2 newClientCert = null;
                X509Certificate2 returnCert = null;
                try
                {
                    newClientCert = LoadPkcs12(newPfxData);
                    returnCert = LoadPkcs12(newPfxData);

                    certCacheLock.EnterWriteLock();
                    try
                    {
                        ThrowIfDisposed();

                        X509Certificate2 oldClientCert = clientCert;
                        byte[] oldPfxData = clientCertPkcs12;

                        clientCert = newClientCert;
                        clientCertPkcs12 = newPfxData;
                        newClientCert = null;
                        newPfxData = null;

                        oldClientCert?.Dispose();
                        ClearPfxData(oldPfxData);
                    }
                    finally
                    {
                        certCacheLock.ExitWriteLock();
                    }

                    return returnCert;
                }
                catch
                {
                    returnCert?.Dispose();
                    newClientCert?.Dispose();
                    ClearPfxData(newPfxData);
                    throw;
                }
            }
            finally
            {
                certRefreshLock.Release();
            }
        }

        private bool TryGetCachedCertificate(out X509Certificate2 certificate)
        {
            certCacheLock.EnterReadLock();
            try
            {
                // X509Certificate2.NotAfter is in LocalTime so compare to DateTime.Now.
                if (clientCert != null && clientCert.NotAfter > DateTime.Now.Add(refreshWindow))
                {
                    certificate = LoadPkcs12(clientCertPkcs12);
                    return true;
                }
            }
            finally
            {
                certCacheLock.ExitReadLock();
            }

            certificate = null;
            return false;
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref disposed) != 0)
                throw new ObjectDisposedException(nameof(RemoteCertSource));
        }

        private static X509Certificate2 LoadPkcs12(byte[] pfxData)
        {
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadPkcs12(pfxData, password: null);
#else
            return new X509Certificate2(
                pfxData,
                (string)null);
#endif
        }

        private static void ClearPfxData(byte[] pfxData)
        {
            if (pfxData != null)
                CryptographicOperations.ZeroMemory(pfxData);
        }

        private static async Task<T> RetryWithBackoffAsync<T>(
            Func<Task<T>> action,
            int retries = 5,
            CancellationToken cancellationToken = default)
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
                    await Task.Delay(backoff, cancellationToken);
                }
            }
            return await action();
        }

        private static bool IsRetryableException(Exception ex)
            => ex is GoogleApiException gex && (int)gex.HttpStatusCode >= 500;
    }
}
