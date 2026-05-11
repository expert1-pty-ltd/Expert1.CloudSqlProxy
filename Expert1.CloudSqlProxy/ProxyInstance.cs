using Expert1.CloudSqlProxy.Auth;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Expert1.CloudSqlProxy
{
    /// <summary>
    /// Represents a local proxy for a Google Cloud SQL instance.
    /// </summary>
    /// <remarks>
    /// Use <see cref="DataSource"/> in your database connection string, then dispose
    /// the instance when the caller no longer needs the proxy.
    /// </remarks>
    public sealed class ProxyInstance : IDisposable
    {
        private readonly ProxyInstanceInternal proxyInstance;
        private int disposeSignaled;

        internal ProxyInstance(ProxyInstanceInternal proxyInstance)
        {
            this.proxyInstance = proxyInstance ?? throw new ArgumentNullException(nameof(proxyInstance));
        }

        /// <summary>
        /// Google Cloud SQL Instance string.
        /// </summary>
        public string Instance => proxyInstance.Instance;

        /// <summary>
        /// The port number that the proxy is listening on.
        /// </summary>
        public int Port => proxyInstance.Port;

        /// <summary>
        /// The Server and Port concatenated together eg. "127.0.0.1,1234".
        /// </summary>
        public string DataSource => proxyInstance.DataSource;

        /// <summary>
        /// Start the proxy instance. This method will block until the proxy is connected.
        /// </summary>
        /// <param name="authenticationMethod">authentication method</param>
        /// <param name="instance">instance</param>
        /// <param name="credentials">credential file or json</param>
        public static async Task<ProxyInstance> StartProxyAsync(
            AuthenticationMethod authenticationMethod,
            string instance,
            string credentials)
        {
            ProxyInstance proxyInstance = await InstanceManager.GetOrCreateInstanceAsync(authenticationMethod, instance, credentials).ConfigureAwait(false);
            return await PrepareLeaseAsync(proxyInstance).ConfigureAwait(false);
        }

        /// <summary>
        /// Start the proxy instance. This method will block until the proxy is connected.
        /// </summary>
        /// <param name="instance">Cloud SQL instance connection name.</param>
        /// <param name="accessTokenSource">Source for Google Cloud access tokens.</param>
        public static async Task<ProxyInstance> StartProxyAsync(
            string instance,
            IAccessTokenSource accessTokenSource)
        {
            ProxyInstance proxyInstance = await InstanceManager.GetOrCreateInstanceAsync(instance, accessTokenSource).ConfigureAwait(false);
            return await PrepareLeaseAsync(proxyInstance).ConfigureAwait(false);
        }

        /// <summary>
        /// Start the proxy instance. This method will block until the proxy is connected.
        /// </summary>
        public static ProxyInstance StartProxy(
            string instance,
            IAccessTokenSource accessTokenSource)
        {
            return StartProxyAsync(instance, accessTokenSource).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Start the proxy instance. This method will block until the proxy is connected.
        /// </summary>
        /// <param name="authenticationMethod">authentication method</param>
        /// <param name="instance">instance</param>
        /// <param name="credentials">credential file or json</param>
        public static ProxyInstance StartProxy(
            AuthenticationMethod authenticationMethod,
            string instance,
            string credentials)
        {
            return StartProxyAsync(authenticationMethod, instance, credentials).GetAwaiter().GetResult();
        }

        internal async Task PrepareConnectionAsync()
            => await proxyInstance.PrepareConnectionAsync();

        private static async Task<ProxyInstance> PrepareLeaseAsync(ProxyInstance proxyInstance)
        {
            try
            {
                await proxyInstance.PrepareConnectionAsync().ConfigureAwait(false);
                return proxyInstance;
            }
            catch
            {
                proxyInstance.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Stops all running ProxyInstances in the current process.
        /// </summary>
        public static void StopAllInstances() => InstanceManager.StopAllInstances();

        /// <inheritdoc/>
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposeSignaled, 1) == 0)
                InstanceManager.RemoveInstance(proxyInstance);
        }
    }
}
