using System;
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
        private readonly Queue<TcpClient> readyConnections = new();
        private readonly SemaphoreSlim capacity;
        private readonly string serverAddress;
        private readonly int serverPort;
        private readonly Timer cleanupTimer;
        private bool disposed;
#if NET9_0_OR_GREATER
        private readonly Lock sync = new();
#else
        private readonly object sync = new();
#endif

        public BackendConnectionManager(
            string serverAddress,
            int serverPort,
            int maxConnections,
            TimeSpan prewarmedConnectionValidationInterval)
        {
            if (maxConnections <= 0)
                throw new ArgumentOutOfRangeException(nameof(maxConnections));

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

            TcpClient connection = null;
            bool queued = false;
            try
            {
                connection = await CreateNewConnectionAsync(cancellationToken).ConfigureAwait(false);

                lock (sync)
                {
                    if (disposed)
                        throw new ObjectDisposedException(nameof(BackendConnectionManager));

                    readyConnections.Enqueue(connection);
                    connection = null;
                    queued = true;
                }
            }
            finally
            {
                if (!queued)
                {
                    connection?.Dispose();
                    ReleaseCapacity();
                }
            }
        }

        public async Task<BackendConnectionLease> RentConnectionAsync(CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();

            if (TryRentReadyConnection(out BackendConnectionLease readyLease))
                return readyLease;

            await capacity.WaitAsync(cancellationToken).ConfigureAwait(false);

            TcpClient connection = null;
            bool leased = false;
            try
            {
                connection = await CreateNewConnectionAsync(cancellationToken).ConfigureAwait(false);
                lock (sync)
                {
                    if (disposed)
                        throw new ObjectDisposedException(nameof(BackendConnectionManager));

                    leased = true;
                    return new BackendConnectionLease(this, connection);
                }
            }
            finally
            {
                if (!leased)
                {
                    connection?.Dispose();
                    ReleaseCapacity();
                }
            }
        }

        private bool TryRentReadyConnection(out BackendConnectionLease lease)
        {
            lock (sync)
            {
                if (disposed)
                    throw new ObjectDisposedException(nameof(BackendConnectionManager));

                while (readyConnections.Count > 0)
                {
                    TcpClient readyConnection = readyConnections.Dequeue();
                    if (IsConnectionValid(readyConnection))
                    {
                        lease = new BackendConnectionLease(this, readyConnection);
                        return true;
                    }

                    readyConnection.Dispose();
                    ReleaseCapacityCore();
                }
            }

            lease = null;
            return false;
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
            lock (sync)
            {
                ReleaseCapacityCore();
            }
        }

        private void ReleaseCapacityCore()
        {
            if (disposed) return;
            capacity.Release();
        }

        private void ThrowIfDisposed()
        {
            lock (sync)
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
            lock (sync)
            {
                if (disposed)
                    return;

                int connectionsToCheck = readyConnections.Count;

                for (int i = 0; i < connectionsToCheck; i++)
                {
                    TcpClient connection = readyConnections.Dequeue();
                    if (!IsConnectionValid(connection))
                    {
                        connection.Dispose();
                        ReleaseCapacityCore();
                        continue;
                    }

                    readyConnections.Enqueue(connection);
                }
            }
        }

        public void Dispose()
        {
            lock (sync)
            {
                if (disposed) return;
                disposed = true;

                cleanupTimer.Dispose();
                while (readyConnections.Count > 0)
                {
                    TcpClient connection = readyConnections.Dequeue();
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
