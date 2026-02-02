using System.Threading.Tasks;

namespace Expert1.CloudSqlProxy
{
    internal sealed class ActiveInstancesEntry
    {
        public int RefCount;
        public int CreateStarted; // 0 = not started, 1 = started

        public readonly TaskCompletionSource<bool> ReadyTcs =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ProxyInstance? Instance;
    }
}
