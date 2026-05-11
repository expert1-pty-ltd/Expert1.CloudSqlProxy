using Expert1.CloudSqlProxy.Auth;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Services;
using Google.Apis.SQLAdmin.v1beta4;
using Google.Apis.SQLAdmin.v1beta4.Data;
using System;
using System.Buffers;
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
        private BackendConnectionManager backendConnections;

        /// <summary>
        /// Google Cloud SQL Instance string.
        /// </summary>
        public string Instance => $"{project}:{region}:{instanceId}";

        private string TargetHost => $"{project}:{instanceId}";

        internal ProxyInstanceInternal(AuthenticationMethod authenticationMethod, string instance, string credentials)
        {
            (project, region, instanceId) = Utilities.SplitName(instance);
            GoogleCredential credential = authenticationMethod == AuthenticationMethod.CredentialFile
                ? GoogleCredential.FromFile(credentials).CreateScoped(SQLAdminService.Scope.CloudPlatform)
                : GoogleCredential.FromJson(credentials).CreateScoped(SQLAdminService.Scope.CloudPlatform);
            sqlAdminService = new SQLAdminService(new BaseClientService.Initializer
            {
                HttpClientInitializer = credential,
                ApplicationName = Utilities.UserAgent
            });

            certSource = new RemoteCertSource(sqlAdminService, instance);
        }

        internal ProxyInstanceInternal(string instance, IAccessTokenSource accessTokenSource)
        {
            (project, region, instanceId) = Utilities.SplitName(instance);

            sqlAdminService = new SQLAdminService(new BaseClientService.Initializer
            {
                HttpClientInitializer = new AccessTokenHttpClientInitializer(accessTokenSource),
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

        internal async Task PrewarmConnectionAsync()
            => await backendConnections.PrewarmConnectionAsync(cts.Token);

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

        internal async Task StartAsync()
        {
            cts = new CancellationTokenSource();
            await SetupServerCertificateAsync();
            await SetupBackendConnectionManager();

            listener = new TcpListener(IPAddress.Loopback, 0); // Listen on a random port
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port; // Get the assigned port
            listeningTask = ListenForConnectionsAsync(cts.Token);
        }

        private async Task SetupBackendConnectionManager()
        {
            DatabaseInstance instanceDetails = await sqlAdminService.Instances.Get(project, instanceId).ExecuteAsync();

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

        private async Task SetupServerCertificateAsync()
        {
            if (serverCaCert == null)
            {
                ConnectSettings connectSettings = await sqlAdminService.Connect.Get(project, instanceId).ExecuteAsync(cts.Token);
                serverCaCert = X509Certificate2.CreateFromPem(connectSettings.ServerCaCert.Cert.AsSpan());
            }
        }

        private async Task ListenForConnectionsAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    TcpClient client = await listener.AcceptTcpClientAsync(cancellationToken);
                    _ = HandleClientAsync(client, cancellationToken); // Fire-and-forget
                }
                catch (OperationCanceledException)
                {
                    // Listener was stopped, exit the loop
                    break;
                }
            }
        }

        private async Task HandleClientAsync(TcpClient client, CancellationToken globalCancellationToken)
        {
            try
            {
                // Create a linked CTS to manage cancellation for this specific connection
                using var connectionCts = CancellationTokenSource.CreateLinkedTokenSource(globalCancellationToken);
                CancellationToken cancellationToken = connectionCts.Token;

                using BackendConnectionManager.BackendConnectionLease serverConnection =
                    await backendConnections.RentConnectionAsync(cancellationToken);

                try
                {
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
                finally
                {
                    client.Dispose();
                }
            }
            catch (OperationCanceledException)
            {
                // Handle expected cancellation gracefully
            }
        }

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
                ArrayPool<byte>.Shared.Return(buffer, true); // Optionally clear the buffer before returning it
            }
        }

        private async Task<SslStream> SetupSecureConnectionAsync(
            NetworkStream networkStream,
            CancellationToken cancellationToken)
        {
            X509Certificate2 cert = await certSource.GetValidClientCertificateAsync(cancellationToken);
            // The client certificate is only needed during TLS authentication.
            // Once authenticated, the SslStream uses negotiated session keys.
            using X509Certificate2 clientCertificate = cert;
            X509Certificate2Collection certCollection = [clientCertificate];
            SslStream sslStream = new(networkStream, false, new RemoteCertificateValidationCallback(ValidateServerCertificate));
            try
            {
                await sslStream.AuthenticateAsClientAsync(
                    TargetHost,
                    certCollection,
                    SslProtocols.Tls13,
                    checkCertificateRevocation: false);
                return sslStream;
            }
            catch
            {
                sslStream.Dispose();
                throw;
            }
        }

        private bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // We require X509Certificate2 for proper chain validation
            if (certificate is not X509Certificate2 cert)
                return false;

            // Enforce strict certificate pinning:
            // - Ignore all system/root CAs
            // - Trust ONLY the Cloud SQL server CA we fetched
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

            // Ensure no accidental roots linger
            chain.ChainPolicy.CustomTrustStore.Clear();
            chain.ChainPolicy.CustomTrustStore.Add(serverCaCert);

            // Cloud SQL certs do not require revocation checking here
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            // Perform a full verification with no relaxations
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            // Build the chain:
            // - Succeeds ONLY if the server certificate chains to serverCaCert
            // - Fails if it chains to any system or public CA
            return chain.Build(cert);
        }
    }
}
