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
        private readonly SemaphoreSlim connectionAvailable;
        private readonly string serverAddress;
        private readonly int serverPort;
        private readonly Timer cleanupTimer;
        // Protected by sync. Concurrent readiness checks share this task so they
        // ensure one warm connection instead of reserving one socket per proxy lease.
        private Task prewarmTask;
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
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxConnections);

            this.serverAddress = serverAddress;
            this.serverPort = serverPort;
            capacity = new SemaphoreSlim(maxConnections, maxConnections);
            connectionAvailable = new SemaphoreSlim(0, maxConnections);
            cleanupTimer = new Timer(
                CleanupInvalidReadyConnections,
                null,
                prewarmedConnectionValidationInterval,
                prewarmedConnectionValidationInterval);
        }

        public Task EnsurePrewarmedConnectionAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            lock (sync)
            {
                ObjectDisposedException.ThrowIf(disposed, typeof(BackendConnectionManager));

                if (HasValidReadyConnectionCore())
                    return Task.CompletedTask;

                if (prewarmTask is null || prewarmTask.IsCompleted)
                    prewarmTask = CreatePrewarmedConnectionAsync(cancellationToken);

                return prewarmTask;
            }
        }

        private async Task CreatePrewarmedConnectionAsync(CancellationToken cancellationToken)
        {
            await capacity.WaitAsync(cancellationToken).ConfigureAwait(false);

            TcpClient connection = null;
            bool queued = false;
            try
            {
                connection = await CreateNewConnectionAsync(cancellationToken).ConfigureAwait(false);

                lock (sync)
                {
                    ObjectDisposedException.ThrowIf(disposed, typeof(BackendConnectionManager));

                    readyConnections.Enqueue(connection);
                    connection = null;
                    queued = true;
                    SignalConnectionAvailableCore();
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

        private bool HasValidReadyConnectionCore()
        {
            while (readyConnections.Count > 0)
            {
                TcpClient readyConnection = readyConnections.Peek();
                if (IsConnectionValid(readyConnection))
                    return true;

                readyConnections.Dequeue();
                readyConnection.Dispose();
                ReleaseCapacityCore();
            }

            return false;
        }

        public ValueTask<BackendConnectionLease> RentConnectionAsync(CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();

            if (TryRentReadyConnection(out BackendConnectionLease readyLease))
                return new ValueTask<BackendConnectionLease>(readyLease);

            if (TryReserveCapacity())
                return new ValueTask<BackendConnectionLease>(CreateLeasedConnectionAsync(cancellationToken));

            return new ValueTask<BackendConnectionLease>(RentConnectionSlowAsync(cancellationToken));
        }

        private async Task<BackendConnectionLease> CreateLeasedConnectionAsync(CancellationToken cancellationToken)
        {
            TcpClient connection = null;
            bool leased = false;
            try
            {
                connection = await CreateNewConnectionAsync(cancellationToken).ConfigureAwait(false);
                lock (sync)
                {
                    ObjectDisposedException.ThrowIf(disposed, typeof(BackendConnectionManager));

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

        private async Task<BackendConnectionLease> RentConnectionSlowAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (TryRentReadyConnection(out BackendConnectionLease readyLease))
                    return readyLease;

                if (TryReserveCapacity())
                    return await CreateLeasedConnectionAsync(cancellationToken).ConfigureAwait(false);

                await WaitForConnectionAvailableAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        private bool TryReserveCapacity()
        {
            lock (sync)
            {
                ObjectDisposedException.ThrowIf(disposed, typeof(BackendConnectionManager));

                return capacity.Wait(0);
            }
        }

        private bool TryRentReadyConnection(out BackendConnectionLease lease)
        {
            lock (sync)
            {
                ObjectDisposedException.ThrowIf(disposed, typeof(BackendConnectionManager));

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

        private async Task WaitForConnectionAvailableAsync(CancellationToken cancellationToken)
        {
            try
            {
                await connectionAvailable.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ObjectDisposedException)
            {
                throw new ObjectDisposedException(nameof(BackendConnectionManager));
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
            lock (sync)
            {
                ReleaseCapacityCore();
            }
        }

        private void ReleaseCapacityCore()
        {
            if (disposed) return;
            capacity.Release();
            SignalConnectionAvailableCore();
        }

        private void SignalConnectionAvailableCore()
        {
            if (disposed)
                return;

            try
            {
                connectionAvailable.Release();
            }
            catch (SemaphoreFullException)
            {
                // A bounded notification is already pending for each possible connection slot.
            }
        }

        private void ThrowIfDisposed()
        {
            lock (sync)
            {
                ObjectDisposedException.ThrowIf(disposed, typeof(BackendConnectionManager));
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
                connectionAvailable.Dispose();
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
