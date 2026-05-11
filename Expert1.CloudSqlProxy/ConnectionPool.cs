using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Expert1.CloudSqlProxy
{
    /// <summary>
    /// Represents a pool of reusable TCP connections to a server, 
    /// designed to reduce the overhead of repeatedly creating and 
    /// tearing down connections for each client request.
    /// </summary>
    internal sealed class ConnectionPool : IDisposable
    {
        private readonly ConcurrentBag<TcpClient> _pool = [];
        private readonly SemaphoreSlim _semaphore;
        private readonly string _serverAddress;
        private readonly int _serverPort;
        private readonly Timer _cleanupTimer;
        private bool _disposed = false;
#if NET9_0_OR_GREATER
        private readonly Lock _disposeLock = new();
#else
        private readonly object _disposeLock = new();
#endif

        /// <summary>
        /// Initializes a new instance of the <see cref="ConnectionPool"/> class.
        /// </summary>
        /// <param name="serverAddress">The address of the server to connect to.</param>
        /// <param name="serverPort">The port number of the server to connect to.</param>
        /// <param name="maxConnections">The maximum number of connections the pool can manage simultaneously.</param>
        /// <param name="connectionIdleTimeout">
        /// The interval at which idle connections are checked and cleaned up.
        /// </param>
        public ConnectionPool(string serverAddress, int serverPort, int maxConnections, TimeSpan connectionIdleTimeout)
        {
            _serverAddress = serverAddress;
            _serverPort = serverPort;
            _semaphore = new SemaphoreSlim(maxConnections, maxConnections);

            // Start a timer for cleaning up idle connections
            _cleanupTimer = new Timer(CleanupIdleConnections, null, connectionIdleTimeout, connectionIdleTimeout);
        }

        /// <summary>
        /// Acquires a connection from the pool. If no connections are available,
        /// a new connection is created, provided the maximum connection limit
        /// has not been reached.
        /// </summary>
        /// <param name="cancellationToken">
        /// A token to monitor for cancellation requests.
        /// </param>
        /// <returns>A <see cref="TcpClient"/> representing the server connection.</returns>
        /// <exception cref="OperationCanceledException">
        /// Thrown if the operation is canceled via the <paramref name="cancellationToken"/>.
        /// </exception>
        public async Task<TcpClient> AcquireConnectionAsync(CancellationToken cancellationToken)
        {
            await _semaphore.WaitAsync(cancellationToken);

            bool connectionReturned = false;
            try
            {
                // Try to reuse an existing connection
                if (_pool.TryTake(out TcpClient connection))
                {
                    if (IsConnectionValid(connection))
                    {
                        connectionReturned = true;
                        return connection;
                    }

                    connection.Dispose();
                }

                // Create a new connection if none are available
                TcpClient newConnection = await CreateNewConnectionAsync(cancellationToken);
                connectionReturned = true;
                return newConnection;
            }
            finally
            {
                if (!connectionReturned)
                {
                    ReleaseSemaphore();
                }
            }
        }

        /// <summary>
        /// Releases a connection back into the pool. If the connection is invalid,
        /// it is disposed of instead.
        /// </summary>
        /// <param name="connection">The <see cref="TcpClient"/> to release.</param>
        public void ReleaseConnection(TcpClient connection)
        {
            lock (_disposeLock)
            {
                if (_disposed)
                {
                    connection.Dispose();
                    return;
                }

                if (IsConnectionValid(connection))
                {
                    _pool.Add(connection);
                }
                else
                {
                    connection.Dispose();
                }

                _semaphore.Release();
            }
        }

        public async Task PrepareConnectionAsync(CancellationToken cancellationToken)
        {
            TcpClient connection = await AcquireConnectionAsync(cancellationToken);
            ReleaseConnection(connection);
        }

        private async Task<TcpClient> CreateNewConnectionAsync(CancellationToken cancellationToken)
        {
            TcpClient client = new();
            try
            {
                await client.ConnectAsync(_serverAddress, _serverPort, cancellationToken);
                return client;
            }
            catch
            {
                client.Dispose();
                throw;
            }
        }

        private void ReleaseSemaphore()
        {
            lock (_disposeLock)
            {
                if (_disposed) return;
                _semaphore.Release();
            }
        }

        private static bool IsConnectionValid(TcpClient connection)
        {
            try
            {
                return connection.Connected && !(connection.Client.Poll(1, SelectMode.SelectRead) && connection.Client.Available == 0);
            }
            catch
            {
                return false;
            }
        }

        private void CleanupIdleConnections(object state)
        {
            List<TcpClient> validConnections = [];
            int connectionsToCheck = _pool.Count;

            for (int i = 0; i < connectionsToCheck && _pool.TryTake(out TcpClient connection); i++)
            {
                if (!IsConnectionValid(connection))
                {
                    connection.Dispose();
                    continue;
                }

                validConnections.Add(connection);
            }

            lock (_disposeLock)
            {
                if (_disposed)
                {
                    foreach (TcpClient connection in validConnections)
                    {
                        connection.Dispose();
                    }

                    return;
                }

                foreach (TcpClient connection in validConnections)
                {
                    _pool.Add(connection);
                }
            }
        }

        /// <summary>
        /// Releases all resources used by the connection pool, including
        /// any active connections and timers.
        /// </summary>
        public void Dispose()
        {
            lock (_disposeLock)
            {
                if (_disposed) return;
                _disposed = true;

                _cleanupTimer.Dispose();
                while (_pool.TryTake(out TcpClient connection))
                {
                    connection.Dispose();
                }
                _semaphore.Dispose();
            }
        }
    }
}
