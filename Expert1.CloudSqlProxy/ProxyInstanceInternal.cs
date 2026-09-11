using Expert1.CloudSqlProxy.Auth;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Http;
using Google.Apis.Services;
using Google.Apis.SQLAdmin.v1beta4;
using Google.Apis.SQLAdmin.v1beta4.Data;
using System;
using System.Buffers;
using System.Collections.Concurrent;
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
        private readonly string project;
        private readonly string region;
        private readonly string instanceId;
        private readonly SQLAdminService sqlAdminService;
        private TcpListener listener;
        private CancellationTokenSource cts;
        private Task listeningTask;
        private readonly RemoteCertSource certSource;
        private X509Certificate2 serverCaCert;
        private string targetHost;
        private bool requireHostnameValidation;
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
            targetHost = $"{project}:{instanceId}";
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

        internal Task PrewarmConnectionAsync()
            => backendConnections.EnsurePrewarmedConnectionAsync(cts.Token);

        private async Task StopAsync(CancellationToken cancellationToken)
        {
            // Signal all background work to stop
            cts.Cancel();

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
                serverCaCert?.Dispose();
                serverCaCert = null;

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
            Task serverCertificateTask = SetupServerCertificateAsync(cts.Token);
            Task backendConnectionManagerTask = SetupBackendConnectionManager(cts.Token);
            await Task.WhenAll(serverCertificateTask, backendConnectionManagerTask).ConfigureAwait(false);
            cts.Token.ThrowIfCancellationRequested();

            listener = new TcpListener(IPAddress.Loopback, 0); // Listen on a random port
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port; // Get the assigned port
            listeningTask = ListenForConnectionsAsync(cts.Token);
        }

        private async Task SetupBackendConnectionManager(CancellationToken cancellationToken)
        {
            DatabaseInstance instanceDetails = await sqlAdminService.Instances.Get(project, instanceId).ExecuteAsync(cancellationToken);

            string serverIp =
                instanceDetails.IpAddresses?
                    .FirstOrDefault(x => string.Equals(x.Type, "PRIMARY", StringComparison.OrdinalIgnoreCase))
                    ?.IpAddress
                ?? instanceDetails.IpAddresses?
                    .FirstOrDefault(x => string.Equals(x.Type, "PRIVATE", StringComparison.OrdinalIgnoreCase))
                    ?.IpAddress
                ?? instanceDetails.IpAddresses?
                    .FirstOrDefault()
                    ?.IpAddress;

            if (string.IsNullOrWhiteSpace(serverIp))
                throw new InvalidOperationException("Cloud SQL instance has no usable IP addresses.");

            backendConnections = new BackendConnectionManager(
                serverIp,
                SQL_PORT,
                MAX_POOL_SIZE,
                TimeSpan.FromMinutes(PREWARMED_CONNECTION_VALIDATION_INTERVAL_MIN));
        }

        private async Task SetupServerCertificateAsync(CancellationToken cancellationToken)
        {
            if (serverCaCert == null)
            {
                ConnectSettings connectSettings = await sqlAdminService.Connect
                    .Get(project, instanceId)
                    .ExecuteAsync(cancellationToken)
                    .ConfigureAwait(false);

                serverCaCert = X509Certificate2.CreateFromPem(connectSettings.ServerCaCert.Cert.AsSpan());
                ConfigureServerIdentityValidation(connectSettings);
            }
        }

        private void ConfigureServerIdentityValidation(ConnectSettings connectSettings)
        {
            if (string.IsNullOrWhiteSpace(connectSettings.ServerCaMode) ||
                string.Equals(
                    connectSettings.ServerCaMode,
                    "GOOGLE_MANAGED_INTERNAL_CA",
                    StringComparison.Ordinal))
            {
                // The per-instance CA is unique to this Cloud SQL instance, so validating
                // the certificate chain against that CA also establishes server identity.
                targetHost = $"{project}:{instanceId}";
                requireHostnameValidation = false;
                return;
            }

            if (string.Equals(
                    connectSettings.ServerCaMode,
                    "GOOGLE_MANAGED_CAS_CA",
                    StringComparison.Ordinal) ||
                string.Equals(
                    connectSettings.ServerCaMode,
                    "CUSTOMER_MANAGED_CAS_CA",
                    StringComparison.Ordinal))
            {
                if (string.IsNullOrWhiteSpace(connectSettings.DnsName))
                {
                    throw new InvalidOperationException(
                        $"Cloud SQL did not provide a DNS name for server identity validation " +
                        $"with CA mode '{connectSettings.ServerCaMode}'.");
                }

                // Shared and customer-managed CAs can sign certificates for more than one
                // server, so the API-provided DNS name must also match the certificate SAN.
                targetHost = connectSettings.DnsName;
                requireHostnameValidation = true;
                return;
            }

            throw new InvalidOperationException(
                $"Unsupported Cloud SQL server CA mode '{connectSettings.ServerCaMode}'.");
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
                static (task, state) =>
                {
                    var activeTasks = (ConcurrentDictionary<Task, byte>)state;
                    activeTasks.TryRemove(task, out _);
                },
                activeConnectionTasks,
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
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
            try
            {
                // Create a linked CTS to manage cancellation for this specific connection
                using var connectionCts = CancellationTokenSource.CreateLinkedTokenSource(globalCancellationToken);
                CancellationToken cancellationToken = connectionCts.Token;

                using BackendConnectionManager.BackendConnectionLease serverConnection =
                    await backendConnections.TryRentConnectionAsync(cancellationToken);

                // A queued client can disconnect before we ever read its socket.
                // Reject excess connections instead of retaining unbounded waiters.
                if (serverConnection is null)
                    return;

                using NetworkStream clientStream = client.GetStream();
                using NetworkStream serverStream = serverConnection.Client.GetStream();
                using SslStream sslStream = await SetupSecureConnectionAsync(serverStream, cancellationToken);

                // Set up forwarding between client and server
                Task clientToServerTask = ProxyTrafficAsync(clientStream, sslStream, cancellationToken);
                Task serverToClientTask = ProxyTrafficAsync(sslStream, clientStream, cancellationToken);

                await Task.WhenAny(clientToServerTask, serverToClientTask);

                // Ensure cancellation is requested for the other connection task
                connectionCts.Cancel();
                await Task.WhenAll(clientToServerTask, serverToClientTask);
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
            byte[] buffer = ArrayPool<byte>.Shared.Rent(8192);
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
            chainPolicy.CustomTrustStore.Add(serverCaCert);

            SslClientAuthenticationOptions authenticationOptions = new()
            {
                TargetHost = targetHost,
                ClientCertificates = certCollection,
                EnabledSslProtocols = SslProtocols.Tls13,
                CertificateChainPolicy = chainPolicy
            };

            if (!requireHostnameValidation)
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
