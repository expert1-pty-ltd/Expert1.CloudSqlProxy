using Google.Apis.Auth.OAuth2;
using Google.Apis.Services;
using Google.Apis.SQLAdmin.v1beta4;
using Google.Apis.SQLAdmin.v1beta4.Data;
using System;
using System.Buffers;
using System.IO;
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
        private const int CERT_REFRESH_MIN = 50;
        private const int SQL_PORT = 3307;
        private readonly string project;
        private readonly string region;
        private readonly string instanceId;
        private readonly SQLAdminService sqlAdminService;
        private TcpListener listener;
        private CancellationTokenSource cts;
        private Task listeningTask;
        private readonly RemoteCertSource certSource;
        private Task certificateRefreshTask;
        private X509Certificate2 clientCert;
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

            certSource = new RemoteCertSource(sqlAdminService);
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

        internal void Stop()
        {
            cts.Cancel();
            try
            {
                // Stop and clear the listener
                listener.Stop();
                listener = null;

                // Wait for the tasks to complete or handle the cancellation exception
                certificateRefreshTask?.Wait();
                listeningTask?.Wait();
            }
            catch (AggregateException ex)
            {
                // Handle the case where the task was cancelled
                ex.Handle(inner => inner is OperationCanceledException);
            }
            finally
            {
                // Dispose of the CancellationTokenSource
                cts.Dispose();
                sqlAdminService.Dispose();
                connectionPool.Dispose();
            }
        }

        internal async Task StartAsync()
        {
            cts = new CancellationTokenSource();
            await SetupCertificatesAsync();
            await SetupConnectionPool();

            listener = new TcpListener(IPAddress.Loopback, 0); // Listen on a random port
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port; // Get the assigned port
            certificateRefreshTask = RefreshCertificatesPeriodicallyAsync();
            listeningTask = ListenForConnectionsAsync(cts.Token);
        }

        private async Task SetupConnectionPool()
        {
            DatabaseInstance instanceDetails = await sqlAdminService.Instances.Get(project, instanceId).ExecuteAsync();
            string serverIp = instanceDetails.IpAddresses[0].IpAddress; // Get the first IP address
            connectionPool = new ConnectionPool(serverIp, SQL_PORT, MAX_POOL_SIZE, TimeSpan.FromMinutes(CONNECTION_IDLE_TIMEOUT_MIN));
        }

        private async Task SetupCertificatesAsync()
        {
            ConnectSettings connectSettings = await sqlAdminService.Connect.Get(project, instanceId).ExecuteAsync(cts.Token);
            serverCaCert = X509Certificate2.CreateFromPem(connectSettings.ServerCaCert.Cert.AsSpan());
            clientCert = await certSource.GetCertificateAsync(Instance);
        }

        private async Task RefreshCertificatesPeriodicallyAsync()
        {
            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromMinutes(CERT_REFRESH_MIN), cts.Token);
                    await SetupCertificatesAsync();
                }
                catch (OperationCanceledException)
                {
                    // Task was canceled, exit the loop
                    break;
                }
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

                while (!cancellationToken.IsCancellationRequested)
                {
                    TcpClient serverConnection = await connectionPool.AcquireConnectionAsync(cancellationToken);
                    try
                    {
                        using NetworkStream clientStream = client.GetStream();

                        using NetworkStream serverStream = serverConnection.GetStream();
                        using SslStream sslStream = await SetupSecureConnectionAsync(serverStream);

                        // Get the actual certificate bound to this SslStream
                        X509Certificate2 actualClientCert = sslStream.LocalCertificate as X509Certificate2;
                        DateTime notAfter = actualClientCert.NotAfter;

                        // Set up forwarding between client and server
                        Task clientToServerTask = ProxyTrafficAsync(clientStream, sslStream, notAfter, cancellationToken);
                        Task serverToClientTask = ProxyTrafficAsync(sslStream, clientStream, notAfter, cancellationToken);

                        await Task.WhenAny(clientToServerTask, serverToClientTask);

                        bool expired = DateTime.UtcNow >= notAfter.AddMinutes(-2);

                        // Ensure cancellation is requested for the other connection task
                        connectionCts.Cancel();
                        await Task.WhenAll(clientToServerTask, serverToClientTask);

                        if (expired && clientCert.NotAfter <= DateTime.UtcNow.AddMinutes(5))
                        {
                            await SetupCertificatesAsync();
                            continue; // re-enter loop with new certs
                        }

                        break;
                    }
                    finally
                    {
                        connectionPool.ReleaseConnection(serverConnection);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Handle expected cancellation gracefully
            }
        }

        private static async Task ProxyTrafficAsync(Stream input, Stream output, DateTime notAfter, CancellationToken cancellationToken)
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(8192);
            try
            {
                Array.Clear(buffer, 0, buffer.Length); // Zero out the buffer
                while (!cancellationToken.IsCancellationRequested)
                {
                    if (DateTime.UtcNow >= notAfter.AddMinutes(-2))
                        break;

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

        private async Task<SslStream> SetupSecureConnectionAsync(NetworkStream networkStream)
        {
            X509Certificate2Collection certCollection =
            [
                clientCert,
                serverCaCert
            ];
            SslStream sslStream = new(networkStream, false, new RemoteCertificateValidationCallback(ValidateServerCertificate));
            await sslStream.AuthenticateAsClientAsync(TargetHost, certCollection, SslProtocols.Tls13, checkCertificateRevocation: false);
            return sslStream;
        }

        private bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                return true; // Certificate is valid
            }

            // Validate against the server CA certificate
            chain.ChainPolicy.ExtraStore.Add(serverCaCert);
            if (chain.Build((X509Certificate2)certificate))
            {
                return true;
            }

            // Ensure the server certificate is issued by the CA certificate we added
            X509ChainElement providedRoot = chain.ChainElements[^1]; // Root CA is last or something is broken
            return serverCaCert.Thumbprint == providedRoot.Certificate.Thumbprint; // Is expected Root CA
        }
    }
}
