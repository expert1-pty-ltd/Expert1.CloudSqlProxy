using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Expert1.CloudSqlProxy
{
    /// <summary>
    /// Manages the lifecycle of ProxyInstance objects, ensuring that only one instance
    /// per unique database instance is active at a time. Handles creation, caching, and
    /// disposal of ProxyInstance objects.
    /// </summary>
    internal static class InstanceManager
    {
        private static readonly ConcurrentDictionary<string, ActiveInstancesEntry> activeInstances = new();

        public static async Task<ProxyInstance> GetOrCreateInstanceAsync(
            AuthenticationMethod authenticationMethod,
            string instance,
            string credentials)
        {
            string key = instance;

            // Get or create the entry (cheap)
            ActiveInstancesEntry entry = activeInstances.GetOrAdd(key, _ => new() { RefCount = 0 });

            // Increment real shared refcount
            Interlocked.Increment(ref entry.RefCount);

            // Exactly one thread creates + starts the instance
            if (Interlocked.CompareExchange(ref entry.CreateStarted, 1, 0) == 0)
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        ProxyInstance created = new(authenticationMethod, instance, credentials);
                        entry.Instance = created;

                        await created.StartAsync().ConfigureAwait(false);
                        entry.ReadyTcs.TrySetResult(true);
                    }
                    catch (Exception ex)
                    {
                        entry.ReadyTcs.TrySetException(ex);

                        // Ensure dictionary doesn't hold a permanently broken entry
                        activeInstances.TryRemove(key, out _);

                        // If we did create an instance, stop/cleanup it safely
                        try { entry.Instance?.Stop(); } catch { /* swallow */ }
                    }
                });
            }

            // Await readiness (or failure)
            await entry.ReadyTcs.Task.ConfigureAwait(false);

            // If ReadyTcs completed successfully, Instance must be non-null
            return entry.Instance!;
        }

        public static void RemoveInstance(ProxyInstance instance)
        {
            string key = instance.Instance;

            if (!activeInstances.TryGetValue(key, out var entry))
                return;

            int newCount = Interlocked.Decrement(ref entry.RefCount);

            if (newCount == 0)
            {
                // Ensure only one thread wins the right to stop/cleanup
                if (activeInstances.TryRemove(key, out var removed))
                {
                    removed.Instance.Stop();
                }
            }
            else if (newCount < 0)
            {
                Debug.Fail($"Refcount for {key} dropped below zero");
            }
        }

        public static void StopAllInstances()
        {
            foreach (string key in activeInstances.Keys)
            {
                if (activeInstances.TryRemove(key, out ActiveInstancesEntry value))
                {
                    value.Instance.Stop();
                }
            }
        }
    }
}
