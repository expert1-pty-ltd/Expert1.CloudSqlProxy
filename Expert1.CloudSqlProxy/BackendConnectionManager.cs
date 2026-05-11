using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Expert1.CloudSqlProxy
{
    /// <summary>
    /// Manages unused backend TCP connections that can be prewarmed before a client tunnel needs one.
    /// </summary>
    internal sealed class BackendConnectionManager : IDisposable
    {
        private readonly ConcurrentQueue<TcpClient> readyConnections = new();
        private readonly SemaphoreSlim capacity;
        private readonly string serverAddress;
        private readonly int serverPort;
        private readonly Timer cleanupTimer;
        private bool disposed;
#if NET9_0_OR_GREATER
        private readonly Lock disposeLock = new();
#else
        private readonly object disposeLock = new();
#endif

        public BackendConnectionManager(
            string serverAddress,
            int serverPort,
            int maxConnections,
            TimeSpan prewarmedConnectionValidationInterval)
        {
            this.serverAddress = serverAddress;
            this.serverPort = serverPort;
            capacity = new SemaphoreSlim(maxConnections, maxConnections);
            cleanupTimer = new Timer(
                CleanupInvalidReadyConnections,
                null,
                prewarmedConnectionValidationInterval,
                prewarmedConnectionValidationInterval);
        }

        public async Task PrewarmConnectionAsync(CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            await capacity.WaitAsync(cancellationToken).ConfigureAwait(false);

            bool queued = false;
            try
            {
                TcpClient connection = await CreateNewConnectionAsync(cancellationToken).ConfigureAwait(false);

                lock (disposeLock)
                {
                    if (disposed)
                    {
                        connection.Dispose();
                        throw new ObjectDisposedException(nameof(BackendConnectionManager));
                    }

                    readyConnections.Enqueue(connection);
                    queued = true;
                }
            }
            finally
            {
                if (!queued)
                {
                    ReleaseCapacity();
                }
            }
        }

        public async Task<BackendConnectionLease> RentConnectionAsync(CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();

            while (readyConnections.TryDequeue(out TcpClient readyConnection))
            {
                if (!IsConnectionValid(readyConnection))
                {
                    readyConnection.Dispose();
                    ReleaseCapacity();
                    continue;
                }

                lock (disposeLock)
                {
                    if (disposed)
                    {
                        readyConnection.Dispose();
                        throw new ObjectDisposedException(nameof(BackendConnectionManager));
                    }

                    return new BackendConnectionLease(this, readyConnection);
                }
            }

            await capacity.WaitAsync(cancellationToken).ConfigureAwait(false);

            bool leased = false;
            try
            {
                TcpClient connection = await CreateNewConnectionAsync(cancellationToken).ConfigureAwait(false);

                lock (disposeLock)
                {
                    if (disposed)
                    {
                        connection.Dispose();
                        throw new ObjectDisposedException(nameof(BackendConnectionManager));
                    }

                    leased = true;
                    return new BackendConnectionLease(this, connection);
                }
            }
            finally
            {
                if (!leased)
                {
                    ReleaseCapacity();
                }
            }
        }

        private async Task<TcpClient> CreateNewConnectionAsync(CancellationToken cancellationToken)
        {
            TcpClient client = new();
            try
            {
                await client.ConnectAsync(serverAddress, serverPort, cancellationToken).ConfigureAwait(false);
                return client;
            }
            catch
            {
                client.Dispose();
                throw;
            }
        }

        private void ReleaseCapacity()
        {
            lock (disposeLock)
            {
                if (disposed) return;
                capacity.Release();
            }
        }

        private void ThrowIfDisposed()
        {
            lock (disposeLock)
            {
                if (disposed)
                    throw new ObjectDisposedException(nameof(BackendConnectionManager));
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

        private void CleanupInvalidReadyConnections(object state)
        {
            List<TcpClient> validConnections = [];
            int connectionsToCheck = readyConnections.Count;

            for (int i = 0; i < connectionsToCheck && readyConnections.TryDequeue(out TcpClient connection); i++)
            {
                if (!IsConnectionValid(connection))
                {
                    connection.Dispose();
                    ReleaseCapacity();
                    continue;
                }

                validConnections.Add(connection);
            }

            lock (disposeLock)
            {
                if (disposed)
                {
                    foreach (TcpClient connection in validConnections)
                    {
                        connection.Dispose();
                    }

                    return;
                }

                foreach (TcpClient connection in validConnections)
                {
                    readyConnections.Enqueue(connection);
                }
            }
        }

        public void Dispose()
        {
            lock (disposeLock)
            {
                if (disposed) return;
                disposed = true;

                cleanupTimer.Dispose();
                while (readyConnections.TryDequeue(out TcpClient connection))
                {
                    connection.Dispose();
                }

                capacity.Dispose();
            }
        }

        internal sealed class BackendConnectionLease : IDisposable
        {
            private readonly BackendConnectionManager owner;
            private readonly TcpClient client;
            private int disposed;

            internal BackendConnectionLease(BackendConnectionManager owner, TcpClient client)
            {
                this.owner = owner;
                this.client = client;
            }

            public TcpClient Client => client;

            public void Dispose()
            {
                if (Interlocked.Exchange(ref disposed, 1) != 0)
                    return;

                client.Dispose();
                owner.ReleaseCapacity();
            }
        }
    }
}
