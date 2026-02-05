using Expert1.CloudSqlProxy.Auth;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Expert1.CloudSqlProxy;

/// <summary>
/// Manages the lifecycle of ProxyInstance objects, ensuring that only one instance
/// per unique database instance is active at a time. Handles creation, caching, and
/// disposal of ProxyInstance objects.
/// </summary>
internal static class InstanceManager
{
    private static readonly ConcurrentDictionary<string, ActiveInstancesEntry> activeInstances = new();

    public static Task<ProxyInstance> GetOrCreateInstanceAsync(
        AuthenticationMethod authenticationMethod,
        string instance,
        string credentials)
    {
        return GetOrCreateInstanceCoreAsync(
            key: instance,
            authMode: (int)AuthMode.GoogleCredential,
            createInstance: () => new ProxyInstance(authenticationMethod, instance, credentials));
    }

    public static Task<ProxyInstance> GetOrCreateInstanceAsync(
        string instance,
        IAccessTokenSource accessTokenSource)
    {
        return GetOrCreateInstanceCoreAsync(
            key: instance,
            authMode: (int)AuthMode.AccessTokenSource,
            createInstance: () => new ProxyInstance(instance, accessTokenSource));
    }

    private static async Task<ProxyInstance> GetOrCreateInstanceCoreAsync(
        string key,
        int authMode,
        Func<ProxyInstance> createInstance)
    {
        ActiveInstancesEntry entry = activeInstances.GetOrAdd(key, _ => new() { RefCount = 0 });

        // Fail fast if someone tries to create the same instance with a different auth mode.
        var existingMode = Volatile.Read(ref entry.AuthMode);
        if (existingMode != (int)AuthMode.Unknown && existingMode != authMode)
            throw new InvalidOperationException(
                $"Proxy instance '{key}' is already active with a different authentication mode.");

        // Ensure the mode is set (only needs to be set once)
        Interlocked.CompareExchange(ref entry.AuthMode, authMode, (int)AuthMode.Unknown);

        // Now that we know the mode is OK, increment refcount
        Interlocked.Increment(ref entry.RefCount);

        if (Interlocked.CompareExchange(ref entry.CreateStarted, 1, 0) == 0)
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    ProxyInstance created = createInstance();
                    entry.Instance = created;

                    await created.StartAsync().ConfigureAwait(false);
                    entry.ReadyTcs.TrySetResult(true);
                }
                catch (Exception ex)
                {
                    entry.ReadyTcs.TrySetException(ex);
                    if (!activeInstances.TryRemove(key, out _))
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
                activeInstances.TryRemove(key, out _);

            throw;
        }

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
                try { removed.Instance?.Stop(); } catch { }
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
                try { value.Instance?.Stop(); } catch { }
            }
        }
    }
}
