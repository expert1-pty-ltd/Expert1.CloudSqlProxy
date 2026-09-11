using Expert1.CloudSqlProxy.Auth;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Http;
using Google.Apis.Services;
using Google.Apis.SQLAdmin.v1beta4;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Expert1.CloudSqlProxy
{
    /// <summary>
    /// Owns the shared running proxy resources for a Cloud SQL instance.
    /// </summary>
    /// <remarks>
    /// A single instance is cached by <see cref="InstanceManager"/> while public
    /// <see cref="ProxyInstance"/> objects act as per-caller disposable leases.
    /// </remarks>
    internal sealed class ProxyInstanceInternal
    {
        private const int MAX_POOL_SIZE = 100;
        private const int PREWARMED_CONNECTION_VALIDATION_INTERVAL_MIN = 5;
        private const int SQL_PORT = 3307;
        private static readonly TimeSpan connectionSetupTimeout = TimeSpan.FromSeconds(30);
        private readonly string project;
        private readonly string region;
        private readonly string instanceId;
        private readonly SQLAdminService sqlAdminService;
        private TcpListener listener;
        private CancellationTokenSource cts;
        private Task listeningTask;
        private readonly RemoteCertSource certSource;
        private BackendConnectionManager backendConnections;
        private readonly ConcurrentDictionary<Task, byte> activeConnectionTasks = new();

        /// <summary>
        /// Google Cloud SQL Instance string.
        /// </summary>
        public string Instance => $"{project}:{region}:{instanceId}";

        internal ProxyInstanceInternal(AuthenticationMethod authenticationMethod, string instance, string credentials)
            : this(instance, Utilities.CreateGoogleCredential(authenticationMethod, credentials))
        {
        }

        internal ProxyInstanceInternal(string instance, GoogleCredential credential)
            : this(instance, (IConfigurableHttpClientInitializer)CreateSqlAdminCredential(credential))
        {
        }

        internal ProxyInstanceInternal(string instance, IAccessTokenSource accessTokenSource)
            : this(instance, CreateAccessTokenInitializer(accessTokenSource))
        {
        }

        private ProxyInstanceInternal(string instance, IConfigurableHttpClientInitializer httpClientInitializer)
        {
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(httpClientInitializer);

            (project, region, instanceId) = Utilities.SplitName(instance);
            sqlAdminService = new SQLAdminService(new BaseClientService.Initializer
            {
                HttpClientInitializer = httpClientInitializer,
                ApplicationName = Utilities.UserAgent
            });

            certSource = new RemoteCertSource(sqlAdminService, instance);
        }

        /// <summary>
        /// The port number that the proxy is listening on.
        /// </summary>
        public int Port { get; private set; }

        /// <summary>
        /// The Server and Port concatenated together eg. "127.0.0.1,1234".
        /// </summary>
        public string DataSource => $"127.0.0.1,{Port}";

        private async Task StopAsync(CancellationToken cancellationToken)
        {
            // Signal all background work to stop
            Utilities.CancelIgnoringCallbackErrors(cts);

            // Stop accepting new connections immediately
            listener?.Stop();
            listener = null;

            // Await background tasks with cancellation
            try
            {
                if (listeningTask is not null)
                    await listeningTask.WaitAsync(cancellationToken).ConfigureAwait(false);

                await WaitForActiveConnectionsAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected during shutdown or timeout
            }
            finally
            {
                // Dispose certificate resources before disposing dependencies they may use
                certSource?.Dispose();

                cts.Dispose();
                sqlAdminService?.Dispose();
                backendConnections?.Dispose();
            }
        }

        internal void Stop()
        {
            using CancellationTokenSource timeoutCts = new(TimeSpan.FromSeconds(5));

            try
            {
                StopAsync(timeoutCts.Token).GetAwaiter().GetResult();
            }
            catch (OperationCanceledException)
            {
                // timed out - optional log
            }
        }

        internal async Task StartAsync(CancellationToken cancellationToken)
        {
            cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            ServerCertificateSettings settings = await certSource
                .GetServerCertificateSettingsAsync(cts.Token)
                .ConfigureAwait(false);
            SetupBackendConnectionManager(settings.ServerIp);

            // Establish initial connectivity once for the shared instance. Acquiring
            // another lease must not depend on spare backend connection capacity.
            await backendConnections.EnsurePrewarmedConnectionAsync(cts.Token).ConfigureAwait(false);
            cts.Token.ThrowIfCancellationRequested();

            listener = new TcpListener(IPAddress.Loopback, 0); // Listen on a random port
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port; // Get the assigned port
            listeningTask = ListenForConnectionsAsync(cts.Token);
        }

        private void SetupBackendConnectionManager(string serverIp)
        {
            if (string.IsNullOrWhiteSpace(serverIp))
                throw new InvalidOperationException("Cloud SQL instance has no usable IP addresses.");

            backendConnections = new BackendConnectionManager(
                serverIp,
                SQL_PORT,
                MAX_POOL_SIZE,
                TimeSpan.FromMinutes(PREWARMED_CONNECTION_VALIDATION_INTERVAL_MIN));
        }

        private async Task ListenForConnectionsAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    TcpClient client = await listener.AcceptTcpClientAsync(cancellationToken);
                    TrackClientConnection(client, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    // Listener was stopped, exit the loop
                    break;
                }
                catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (SocketException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
            }
        }

        private void TrackClientConnection(TcpClient client, CancellationToken cancellationToken)
        {
            // Keep accepting clients while still giving shutdown a task to wait on.
            Task connectionTask = HandleClientAsync(client, cancellationToken);
            activeConnectionTasks.TryAdd(connectionTask, 0);
            _ = connectionTask.ContinueWith(
                static (task, state) => ((ProxyInstanceInternal)state).CompleteClientConnection(task),
                this,
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }

        private void CompleteClientConnection(Task connectionTask)
        {
            // Reading Exception observes every fault, including failures during cleanup.
            AggregateException failure = connectionTask.Exception;
            activeConnectionTasks.TryRemove(connectionTask, out _);

            if (failure is not null)
                TraceConnectionFailure(failure);
        }

        private void TraceConnectionFailure(AggregateException failure)
        {
            try
            {
                foreach (Exception exception in failure.Flatten().InnerExceptions)
                {
                    // Token providers and API responses can include credentials in messages.
                    Trace.TraceWarning(
                        "Cloud SQL connection for {0} failed ({1}).",
                        Instance, exception.GetType().Name);
                }
            }
            catch
            {
                // A failing trace listener must not fault the connection completion task.
            }
        }

        private async Task WaitForActiveConnectionsAsync(CancellationToken cancellationToken)
        {
            Task[] connectionTasks = activeConnectionTasks.Keys.ToArray();
            if (connectionTasks.Length == 0)
                return;

            await Task.WhenAll(connectionTasks).WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        private async Task HandleClientAsync(TcpClient client, CancellationToken globalCancellationToken)
        {
            CancellationToken cancellationToken = default;
            bool connectionEstablished = false;
            try
            {
                // Create a linked CTS to manage cancellation for this specific connection
                using var connectionCts = CancellationTokenSource.CreateLinkedTokenSource(globalCancellationToken);
                cancellationToken = connectionCts.Token;
                await using var setupTimer = new Timer(
                    static state => Utilities.CancelIgnoringCallbackErrors((CancellationTokenSource)state),
                    connectionCts,
                    connectionSetupTimeout,
                    Timeout.InfiniteTimeSpan);

                using BackendConnectionManager.BackendConnectionLease serverConnection =
                    await backendConnections.TryRentConnectionAsync(cancellationToken);

                // A queued client can disconnect before we ever read its socket.
                // Reject excess connections instead of retaining unbounded waiters.
                if (serverConnection is null)
                    return;

                using NetworkStream clientStream = client.GetStream();
                using NetworkStream serverStream = serverConnection.Client.GetStream();
                using SslStream sslStream = await SetupSecureConnectionAsync(serverStream, cancellationToken);

                // Finish any running timeout callback before establishing the tunnel.
                await setupTimer.DisposeAsync().ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                connectionEstablished = true;

                // Set up forwarding between client and server
                Task clientToServerTask = ProxyTrafficAsync(clientStream, sslStream, cancellationToken);
                Task serverToClientTask = ProxyTrafficAsync(sslStream, clientStream, cancellationToken);

                await Task.WhenAny(clientToServerTask, serverToClientTask);

                // Ensure cancellation is requested for the other connection task
                Utilities.CancelIgnoringCallbackErrors(connectionCts);
                await Task.WhenAll(clientToServerTask, serverToClientTask);
            }
            catch (OperationCanceledException ex) when (
                !connectionEstablished && cancellationToken.IsCancellationRequested &&
                !globalCancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException("Cloud SQL connection setup timed out.", ex);
            }
            catch (Exception ex) when (IsExpectedConnectionClose(ex, globalCancellationToken))
            {
                // The client or Cloud SQL proxy closed the tunnel as part of normal connection teardown.
            }
            finally
            {
                client.Dispose();
            }
        }

        private static bool IsExpectedConnectionClose(Exception ex, CancellationToken cancellationToken)
        {
            if (ex is OperationCanceledException)
                return true;

            if (cancellationToken.IsCancellationRequested &&
                (ex is ObjectDisposedException || ex is IOException || ex is SocketException))
            {
                return true;
            }

            if (ex is IOException { InnerException: SocketException socketException })
                return IsExpectedSocketClose(socketException.SocketErrorCode);

            return ex is SocketException directSocketException &&
                IsExpectedSocketClose(directSocketException.SocketErrorCode);
        }

        private static bool IsExpectedSocketClose(SocketError socketError)
            => socketError is SocketError.ConnectionAborted
                or SocketError.ConnectionReset
                or SocketError.OperationAborted
                or SocketError.Shutdown;

        private static async Task ProxyTrafficAsync(Stream input, Stream output, CancellationToken cancellationToken)
        {
            // Reduce forwarding calls for large transfers while keeping per-tunnel buffers small.
            byte[] buffer = ArrayPool<byte>.Shared.Rent(16 * 1024);
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    int bytesRead = await input.ReadAsync(buffer, cancellationToken);
                    if (bytesRead == 0)
                    {
                        break;
                    }

                    if (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }

                    await output.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
                }
            }
            catch (OperationCanceledException)
            {
                // Handle expected cancellation gracefully
            }
            finally
            {
                // For security purposes, clear the buffer before returning it.
                ArrayPool<byte>.Shared.Return(buffer, true); 
            }
        }

        private async Task<SslStream> SetupSecureConnectionAsync(
            NetworkStream networkStream,
            CancellationToken cancellationToken)
        {
            ServerCertificateSettings serverSettings = await certSource
                .GetServerCertificateSettingsAsync(cancellationToken)
                .ConfigureAwait(false);
            using ServerCertificateSettings.CertificateBundle serverCaCertificates = serverSettings.CreateCertificates();

            X509Certificate2 cert = await certSource
                .GetValidClientCertificateAsync(cancellationToken)
                .ConfigureAwait(false);

            // The client certificate is only needed during TLS authentication.
            // Once authenticated, the SslStream uses negotiated session keys.
            using X509Certificate2 clientCertificate = cert;
            X509Certificate2Collection certCollection = [clientCertificate];

            X509ChainPolicy chainPolicy = new()
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
                VerificationFlags = X509VerificationFlags.NoFlag
            };
            chainPolicy.CustomTrustStore.AddRange(serverCaCertificates.Certificates);

            SslClientAuthenticationOptions authenticationOptions = new()
            {
                TargetHost = serverSettings.TargetHost,
                ClientCertificates = certCollection,
                EnabledSslProtocols = SslProtocols.Tls13,
                CertificateChainPolicy = chainPolicy
            };

            if (!serverSettings.RequireHostnameValidation)
            {
                authenticationOptions.RemoteCertificateValidationCallback =
                    ValidatePerInstanceServerCertificate;
            }

            SslStream sslStream = new(networkStream, leaveInnerStreamOpen: false);
            try
            {
                await sslStream
                    .AuthenticateAsClientAsync(authenticationOptions, cancellationToken)
                    .ConfigureAwait(false);

                return sslStream;
            }
            catch
            {
                sslStream.Dispose();
                throw;
            }
        }

        private static bool ValidatePerInstanceServerCertificate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            // Per-instance Cloud SQL certificates do not consistently expose a hostname
            // suitable for validation. The custom chain policy still requires the unique
            // instance CA; only a name mismatch may be ignored for this CA mode.
            return certificate is not null &&
                chain is not null &&
                (sslPolicyErrors & ~SslPolicyErrors.RemoteCertificateNameMismatch) ==
                    SslPolicyErrors.None;
        }

        private static GoogleCredential CreateSqlAdminCredential(GoogleCredential credential)
        {
            ArgumentNullException.ThrowIfNull(credential);
            return credential.CreateScoped(SQLAdminService.Scope.CloudPlatform);
        }

        private static IConfigurableHttpClientInitializer CreateAccessTokenInitializer(IAccessTokenSource accessTokenSource)
        {
            ArgumentNullException.ThrowIfNull(accessTokenSource);
            return new AccessTokenHttpClientInitializer(accessTokenSource);
        }
    }
}
