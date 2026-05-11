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
    /// Represents a proxy instance that establishes a secure connection between a local client
    /// and a Google Cloud SQL instance. Manages SSL/TLS authentication, traffic forwarding,
    /// and periodic certificate refresh.
    /// </summary>
    public sealed class ProxyInstance : IDisposable
    {
        private const int MAX_POOL_SIZE = 100;
        private const int CONNECTION_IDLE_TIMEOUT_MIN = 5;
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
        private ConnectionPool connectionPool;

        /// <summary>
        /// Google Cloud SQL Instance string
        /// </summary>
        public string Instance => $"{project}:{region}:{instanceId}";
        private string TargetHost => $"{project}:{instanceId}";

        internal ProxyInstance(AuthenticationMethod authenticationMethod, string instance, string credentials)
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

        internal ProxyInstance(string instance, IAccessTokenSource accessTokenSource)
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

        /// <summary>
        /// Start the proxy instance. This method will block until the proxy is connected.
        /// </summary>
        /// <param name="authenticationMethod">authentication method</param>
        /// <param name="instance">instance</param>
        /// <param name="credentials">credential file or json</param>
        public static async Task<ProxyInstance> StartProxyAsync(
            AuthenticationMethod authenticationMethod,
            string instance,
            string credentials)
        {
            ProxyInstance proxyInstance = await InstanceManager.GetOrCreateInstanceAsync(authenticationMethod, instance, credentials).ConfigureAwait(false);
            await proxyInstance.PrepareConnectionAsync().ConfigureAwait(false);
            return proxyInstance;
        }

        /// <summary>
        /// Start the proxy instance. This method will block until the proxy is connected.
        /// </summary>
        /// <param name="instance">Cloud SQL instance connection name.</param>
        /// <param name="accessTokenSource">Source for Google Cloud access tokens.</param>
        public static async Task<ProxyInstance> StartProxyAsync(
            string instance,
            IAccessTokenSource accessTokenSource)
        {
            ProxyInstance proxyInstance = await InstanceManager.GetOrCreateInstanceAsync(instance, accessTokenSource).ConfigureAwait(false);

            await proxyInstance.PrepareConnectionAsync().ConfigureAwait(false);
            return proxyInstance;
        }

        /// <summary>
        /// Start the proxy instance. This method will block until the proxy is connected.
        /// </summary>
        public static ProxyInstance StartProxy(
            string instance,
            IAccessTokenSource accessTokenSource)
        {
            return StartProxyAsync(instance, accessTokenSource).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Start the proxy instance. This method will block until the proxy is connected.
        /// </summary>
        /// <param name="authenticationMethod">authentication method</param>
        /// <param name="instance">instance</param>
        /// <param name="credentials">credential file or json</param>
        public static ProxyInstance StartProxy(
            AuthenticationMethod authenticationMethod,
            string instance,
            string credentials)
        {
            return StartProxyAsync(authenticationMethod, instance, credentials).GetAwaiter().GetResult();
        }


        internal async Task PrepareConnectionAsync()
            => await connectionPool.PrepareConnectionAsync(cts.Token);

        /// <summary>
        /// Stops all running ProxyInstances in the current process.
        /// </summary>
        public static void StopAllInstances() => InstanceManager.StopAllInstances();

        /// <inheritdoc/>
        public void Dispose() => InstanceManager.RemoveInstance(this);

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
                connectionPool?.Dispose();
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
                // timed out – optional log
            }
        }

        internal async Task StartAsync()
        {
            cts = new CancellationTokenSource();
            await SetupServerCertificateAsync();
            await SetupConnectionPool();

            listener = new TcpListener(IPAddress.Loopback, 0); // Listen on a random port
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port; // Get the assigned port
            listeningTask = ListenForConnectionsAsync(cts.Token);
        }

        private async Task SetupConnectionPool()
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

            connectionPool = new ConnectionPool(
                serverIp,
                SQL_PORT,
                MAX_POOL_SIZE,
                TimeSpan.FromMinutes(CONNECTION_IDLE_TIMEOUT_MIN));
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

                TcpClient serverConnection = await connectionPool.AcquireConnectionAsync(cancellationToken);
                try
                {
                    using NetworkStream clientStream = client.GetStream();

                    using NetworkStream serverStream = serverConnection.GetStream();
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
                    connectionPool.ReleaseConnection(serverConnection);
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
