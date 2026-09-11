using Google;
using Google.Apis.SQLAdmin.v1beta4;
using Google.Apis.SQLAdmin.v1beta4.Data;
using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Expert1.CloudSqlProxy
{
    /// <summary>
    /// Manages the retrieval and caching of certificates required for establishing
    /// secure connections to Google Cloud SQL instances. Handles RSA key generation,
    /// ephemeral client certificates, and server CA and identity settings.
    /// </summary>
    internal sealed class RemoteCertSource : IDisposable
    {
#if NET9_0_OR_GREATER
        private readonly Lock keyLock = new();
#else
        private readonly object keyLock = new();
#endif
        private readonly SemaphoreSlim certRefreshLock = new(1, 1);
        private readonly SemaphoreSlim settingsRefreshLock = new(1, 1);
        private readonly ReaderWriterLockSlim certCacheLock = new();
        private readonly SQLAdminService service;
        private RSA privateKey;
        private X509Certificate2 clientCert;
        private ServerCertificateSettings serverCertificateSettings;
        private long serverCertificateRefreshTimestamp;
        private int disposed;
        private int resourcesDisposed;
        private static readonly TimeSpan refreshWindow = TimeSpan.FromMinutes(15);
        private static readonly TimeSpan baseBackoff = TimeSpan.FromMilliseconds(200);
        private static readonly TimeSpan refreshLoopTime = TimeSpan.FromMinutes(50);
        private static readonly TimeSpan initialRefreshRetryDelay = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan maxRefreshRetryDelay = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan disposeRefreshWaitTimeout = TimeSpan.FromSeconds(1);
        private readonly CancellationTokenSource refreshCts;
        private readonly Task refreshTask;
        private readonly string project;
        private readonly string instanceId;
        private readonly string regionName;
        private string publicKeyPem;

        public RemoteCertSource(SQLAdminService service, string instance)
        {
            this.service = service;
            (project, string region, string name) = Utilities.SplitName(instance);
            instanceId = name;
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
            TimeSpan delay = refreshLoopTime;
            TimeSpan retryDelay = initialRefreshRetryDelay;

            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(delay, token).ConfigureAwait(false);
                    await GetServerCertificateSettingsAsync(token).ConfigureAwait(false);
                    using X509Certificate2 certificate = await GetValidClientCertificateAsync(token).ConfigureAwait(false);
                    delay = GetNextRefreshDelay(certificate);
                    retryDelay = initialRefreshRetryDelay;
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    if (token.IsCancellationRequested)
                        break;

                    delay = retryDelay;
                    retryDelay = TimeSpan.FromTicks(Math.Min(retryDelay.Ticks * 2, maxRefreshRetryDelay.Ticks));
                    TraceRefreshFailure(ex, delay);
                }
            }
        }

        private TimeSpan GetNextRefreshDelay(X509Certificate2 certificate)
        {
            certCacheLock.EnterReadLock();
            try
            {
                // A cache hit may be due for renewal before another full interval elapses.
                TimeSpan certificateDelay = certificate.NotAfter - DateTime.Now - refreshWindow;
                TimeSpan settingsDelay = refreshLoopTime - TimeSpan.FromMilliseconds(
                    Environment.TickCount64 - serverCertificateRefreshTimestamp);

                // Check whichever cache is due first, without spinning on short-lived certificates.
                long delayTicks = Math.Min(certificateDelay.Ticks, settingsDelay.Ticks);
                return TimeSpan.FromTicks(Math.Clamp(
                    delayTicks, initialRefreshRetryDelay.Ticks, refreshLoopTime.Ticks));
            }
            finally
            {
                certCacheLock.ExitReadLock();
            }
        }

        private void TraceRefreshFailure(Exception exception, TimeSpan retryDelay)
        {
            try
            {
                // Token providers may include credentials in exception messages.
                Trace.TraceWarning(
                    "Cloud SQL certificate refresh for {0}/{1} failed ({2}); retrying in {3}.",
                    project, regionName, exception.GetType().Name, retryDelay);
            }
            catch
            {
                // A failing trace listener must not stop certificate renewal.
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
                return;

            Utilities.CancelIgnoringCallbackErrors(refreshCts);

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

            if (!settingsRefreshLock.Wait(0))
            {
                certRefreshLock.Release();
                return false;
            }

            DisposeResourcesWithRefreshLocksHeld();
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
            await settingsRefreshLock.WaitAsync().ConfigureAwait(false);
            DisposeResourcesWithRefreshLocksHeld();
        }

        private void DisposeResourcesWithRefreshLocksHeld()
        {
            if (Interlocked.Exchange(ref resourcesDisposed, 1) != 0)
            {
                settingsRefreshLock.Release();
                certRefreshLock.Release();
                return;
            }

            try
            {
                certCacheLock.EnterWriteLock();
                try
                {
                    clientCert?.Dispose();
                    privateKey?.Dispose();
                    clientCert = null;
                    serverCertificateSettings = null;
                    privateKey = null;
                }
                finally
                {
                    certCacheLock.ExitWriteLock();
                }
            }
            finally
            {
                settingsRefreshLock.Release();
                certRefreshLock.Release();
                // Queued callers must be able to acquire the gates and observe
                // disposal. Disposing a semaphore can abandon its async waiters.
                certCacheLock.Dispose();
                refreshCts.Dispose();
            }
        }

        public ValueTask<ServerCertificateSettings> GetServerCertificateSettingsAsync(CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            if (TryGetCachedServerCertificateSettings(out ServerCertificateSettings settings))
                return new ValueTask<ServerCertificateSettings>(settings);

            return new ValueTask<ServerCertificateSettings>(GetServerCertificateSettingsSlowAsync(cancellationToken));
        }

        private async Task<ServerCertificateSettings> GetServerCertificateSettingsSlowAsync(CancellationToken cancellationToken)
        {
            await settingsRefreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                if (TryGetCachedServerCertificateSettings(out ServerCertificateSettings settings))
                    return settings;

                ConnectSettings connectSettings = await service.Connect
                    .Get(project, instanceId)
                    .ExecuteAsync(cancellationToken)
                    .ConfigureAwait(false);
                settings = new ServerCertificateSettings(connectSettings, project, instanceId);

                certCacheLock.EnterWriteLock();
                try
                {
                    ThrowIfDisposed();
                    serverCertificateSettings = settings;
                    serverCertificateRefreshTimestamp = Environment.TickCount64;
                }
                finally
                {
                    certCacheLock.ExitWriteLock();
                }

                return settings;
            }
            finally
            {
                settingsRefreshLock.Release();
            }
        }

        private bool TryGetCachedServerCertificateSettings(out ServerCertificateSettings settings)
        {
            certCacheLock.EnterReadLock();
            try
            {
                settings = serverCertificateSettings;
                return settings != null &&
                    Environment.TickCount64 - serverCertificateRefreshTimestamp < refreshLoopTime.TotalMilliseconds;
            }
            finally
            {
                certCacheLock.ExitReadLock();
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
                    returnCert = new X509Certificate2(newClientCert);

                    certCacheLock.EnterWriteLock();
                    try
                    {
                        ThrowIfDisposed();

                        X509Certificate2 oldClientCert = clientCert;
                        clientCert = newClientCert;
                        newClientCert = null;

                        oldClientCert?.Dispose();
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
                    throw;
                }
                finally
                {
                    ClearPfxData(newPfxData);
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
                    // The copy owns a reference to the certificate and private key,
                    // so it remains usable if the cache is refreshed or disposed.
                    certificate = new X509Certificate2(clientCert);
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
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, typeof(RemoteCertSource));
        }

        private static X509Certificate2 LoadPkcs12(byte[] pfxData)
        {
            // Intentionally do not use EphemeralKeySet. Windows Schannel cannot reliably
            // use ephemeral private keys for SslStream client authentication.
            // DefaultKeySet may use temporary store-backed key material, but because
            // PersistKeySet is not specified, disposing the cached certificate and
            // all its copies removes the key. Callers must dispose every returned copy.
            // See: https://github.com/dotnet/runtime/issues/23749
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadPkcs12(
                pfxData,
                password: null,
                keyStorageFlags: X509KeyStorageFlags.DefaultKeySet);
#else
            return new X509Certificate2(
                pfxData,
                (string)null,
                X509KeyStorageFlags.DefaultKeySet);
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
