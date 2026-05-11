using Expert1.CloudSqlProxy.Auth;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Expert1.CloudSqlProxy;

/// <summary>
/// Manages the lifecycle of shared proxy instances, ensuring that only one running
/// proxy per unique database instance and authentication identity is active at a time.
/// </summary>
internal static class InstanceManager
{
    private static readonly ConcurrentDictionary<ProxyCacheKey, ActiveInstancesEntry> activeInstances = new();

    public static Task<ProxyInstance> GetOrCreateInstanceAsync(
        AuthenticationMethod authenticationMethod,
        string instance,
        string credentials)
    {
        ProxyCacheKey cacheKey = ProxyCacheKey.ForGoogleCredential(authenticationMethod, instance, credentials);

        return GetOrCreateInstanceCoreAsync(
            cacheKey,
            createInstance: () => new ProxyInstanceInternal(authenticationMethod, instance, credentials));
    }

    public static Task<ProxyInstance> GetOrCreateInstanceAsync(
        string instance,
        IAccessTokenSource accessTokenSource)
    {
        ProxyCacheKey cacheKey = ProxyCacheKey.ForAccessTokenSource(instance, accessTokenSource);

        return GetOrCreateInstanceCoreAsync(
            cacheKey,
            createInstance: () => new ProxyInstanceInternal(instance, accessTokenSource));
    }

    private static async Task<ProxyInstance> GetOrCreateInstanceCoreAsync(
        ProxyCacheKey cacheKey,
        Func<ProxyInstanceInternal> createInstance)
    {
        ActiveInstancesEntry entry = activeInstances.GetOrAdd(cacheKey, _ => new() { RefCount = 0 });

        // Each cache key already includes the authentication identity.
        Interlocked.Increment(ref entry.RefCount);

        if (Interlocked.CompareExchange(ref entry.CreateStarted, 1, 0) == 0)
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    ProxyInstanceInternal created = createInstance();
                    entry.Instance = created;

                    await created.StartAsync().ConfigureAwait(false);
                    entry.ReadyTcs.TrySetResult(true);
                }
                catch (Exception ex)
                {
                    entry.ReadyTcs.TrySetException(ex);
                    if (!activeInstances.TryRemove(cacheKey, out _))
                    {
                        // If the entry remained for any reason, allow retry.
                        Volatile.Write(ref entry.CreateStarted, 0);
                    }
                    try { entry.Instance?.Stop(); } catch { /* swallow */ }
                }
            });
        }

        try
        {
            await entry.ReadyTcs.Task.ConfigureAwait(false);
        }
        catch
        {
            // Undo the refcount increment for this caller.
            int newCount = Interlocked.Decrement(ref entry.RefCount);

            // If we were the last "holder", try to remove the entry.
            // (Instance may never have started successfully.)
            if (newCount == 0)
                activeInstances.TryRemove(cacheKey, out _);

            throw;
        }

        return new ProxyInstance(cacheKey, entry.Instance!);
    }

    public static void RemoveInstance(ProxyCacheKey cacheKey)
    {
        if (!activeInstances.TryGetValue(cacheKey, out var entry))
            return;

        int newCount = Interlocked.Decrement(ref entry.RefCount);

        if (newCount == 0)
        {
            // Ensure only one thread wins the right to stop/cleanup
            if (activeInstances.TryRemove(cacheKey, out var removed))
            {
                try { removed.Instance?.Stop(); } catch { }
            }
        }
        else if (newCount < 0)
        {
            Debug.Fail($"Refcount for {cacheKey.Instance} dropped below zero");
        }
    }

    public static void StopAllInstances()
    {
        foreach (ProxyCacheKey key in activeInstances.Keys)
        {
            if (activeInstances.TryRemove(key, out ActiveInstancesEntry value))
            {
                try { value.Instance?.Stop(); } catch { }
            }
        }
    }
}
