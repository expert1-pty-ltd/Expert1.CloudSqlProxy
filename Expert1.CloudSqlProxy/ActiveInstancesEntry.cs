using System;
using System.Threading;
using System.Threading.Tasks;

namespace Expert1.CloudSqlProxy
{
    internal sealed class ActiveInstancesEntry : IDisposable
    {
        private readonly CancellationTokenSource cancellation = new();
        private int disposed;

        public ActiveInstancesEntry(Func<CancellationToken, Task<ProxyInstanceInternal>> startInstance)
        {
            InstanceTask = Task.Run(() => startInstance(cancellation.Token), cancellation.Token);
        }

        public int RefCount;

        public Task<ProxyInstanceInternal> InstanceTask { get; }

        public void Cancel()
        {
            try
            {
                cancellation.Cancel();
            }
            catch (ObjectDisposedException)
            {
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) == 0)
                cancellation.Dispose();
        }
    }
}
