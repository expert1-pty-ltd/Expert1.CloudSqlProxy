using Expert1.CloudSqlProxy.Auth;
using System;
using System.Collections.Generic;
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
#if NET9_0_OR_GREATER
    private static readonly Lock sync = new();
#else
    private static readonly object sync = new();
#endif
    private static readonly Dictionary<ProxyCacheKey, ActiveInstancesEntry> activeInstances = new();

    public static Task<ProxyInstance> GetOrCreateInstanceAsync(
        AuthenticationMethod authenticationMethod,
        string instance,
        string credentials)
    {
        ProxyCacheKey cacheKey = ProxyCacheKey.ForGoogleCredential(authenticationMethod, instance, credentials);

        return GetOrCreateInstanceCoreAsync(
            cacheKey,
            (cancellationToken) => StartInstanceAsync(
                () => new ProxyInstanceInternal(authenticationMethod, instance, credentials),
                cancellationToken));
    }

    public static Task<ProxyInstance> GetOrCreateInstanceAsync(
        string instance,
        IAccessTokenSource accessTokenSource)
    {
        ProxyCacheKey cacheKey = ProxyCacheKey.ForAccessTokenSource(instance, accessTokenSource);

        return GetOrCreateInstanceCoreAsync(
            cacheKey,
            (cancellationToken) => StartInstanceAsync(
                () => new ProxyInstanceInternal(instance, accessTokenSource),
                cancellationToken));
    }

    private static async Task<ProxyInstance> GetOrCreateInstanceCoreAsync(
        ProxyCacheKey cacheKey,
        Func<CancellationToken, Task<ProxyInstanceInternal>> startInstance)
    {
        ActiveInstancesEntry entry;

        lock (sync)
        {
            if (!activeInstances.TryGetValue(cacheKey, out entry))
            {
                entry = new ActiveInstancesEntry(startInstance);
                activeInstances.Add(cacheKey, entry);
            }

            entry.RefCount++;
        }

        try
        {
            ProxyInstanceInternal instance = await entry.InstanceTask.ConfigureAwait(false);

            lock (sync)
            {
                ObjectDisposedException.ThrowIf(!IsCurrentEntry(cacheKey, entry), typeof(ProxyInstance));
                return new ProxyInstance(cacheKey, entry, instance);
            }
        }
        catch
        {
            RemoveFailedEntry(cacheKey, entry);
            ReleaseEntry(cacheKey, entry);
            throw;
        }
    }

    private static async Task<ProxyInstanceInternal> StartInstanceAsync(
        Func<ProxyInstanceInternal> createInstance,
        CancellationToken cancellationToken)
    {
        ProxyInstanceInternal instance = null;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            instance = createInstance();
            await instance.StartAsync(cancellationToken).ConfigureAwait(false);

            return instance;
        }
        catch
        {
            StopInstance(instance);
            throw;
        }
    }

    public static void RemoveInstance(ProxyCacheKey cacheKey, ActiveInstancesEntry entry)
        => ReleaseEntry(cacheKey, entry);

    private static void ReleaseEntry(ProxyCacheKey cacheKey, ActiveInstancesEntry entry)
    {
        Task<ProxyInstanceInternal> instanceTaskToStop = null;
        bool refCountBelowZero = false;

        lock (sync)
        {
            if (!IsCurrentEntry(cacheKey, entry))
                return;

            entry.RefCount--;

            if (entry.RefCount == 0)
            {
                activeInstances.Remove(cacheKey);
                entry.Cancel();
                instanceTaskToStop = entry.InstanceTask;
            }
            else if (entry.RefCount < 0)
            {
                refCountBelowZero = true;
            }
        }

        if (refCountBelowZero)
            Debug.Fail($"Refcount for {cacheKey.Instance} dropped below zero");

        StopWhenReady(instanceTaskToStop, entry);
    }

    private static void RemoveFailedEntry(ProxyCacheKey cacheKey, ActiveInstancesEntry entry)
    {
        if (!entry.InstanceTask.IsFaulted && !entry.InstanceTask.IsCanceled)
            return;

        bool removed = false;

        lock (sync)
        {
            if (IsCurrentEntry(cacheKey, entry))
            {
                activeInstances.Remove(cacheKey);
                removed = true;
            }
        }

        if (removed)
            entry.Dispose();
    }

    private static bool IsCurrentEntry(ProxyCacheKey cacheKey, ActiveInstancesEntry entry)
        => activeInstances.TryGetValue(cacheKey, out ActiveInstancesEntry current) &&
            ReferenceEquals(current, entry);

    private static void StopWhenReady(Task<ProxyInstanceInternal> instanceTask, ActiveInstancesEntry entry)
    {
        if (instanceTask is null)
            return;

        _ = StopWhenReadyAsync(instanceTask, entry);
    }

    private static async Task StopWhenReadyAsync(
        Task<ProxyInstanceInternal> instanceTask,
        ActiveInstancesEntry entry)
    {
        try
        {
            ProxyInstanceInternal instance = await instanceTask.ConfigureAwait(false);
            StopInstance(instance);
        }
        catch
        {
        }
        finally
        {
            entry.Dispose();
        }
    }

    private static void StopInstance(ProxyInstanceInternal instance)
    {
        if (instance is null)
            return;

        try { instance.Stop(); } catch { }
    }

    public static void StopAllInstances()
    {
        List<ActiveInstancesEntry> entriesToStop;

        lock (sync)
        {
            entriesToStop = new List<ActiveInstancesEntry>(activeInstances.Values);
            activeInstances.Clear();

            foreach (ActiveInstancesEntry entry in entriesToStop)
            {
                entry.RefCount = 0;
                entry.Cancel();
            }
        }

        foreach (ActiveInstancesEntry entry in entriesToStop)
        {
            StopWhenReady(entry.InstanceTask, entry);
        }
    }
}
