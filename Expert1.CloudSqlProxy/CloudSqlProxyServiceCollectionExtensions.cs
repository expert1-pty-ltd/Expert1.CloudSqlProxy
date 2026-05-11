using Expert1.CloudSqlProxy.Auth;
using Microsoft.Extensions.DependencyInjection;

namespace Expert1.CloudSqlProxy
{
    /// <summary>
    /// Cloud Sql Proxy specific extension methods for <see cref="IServiceCollection" />.
    /// </summary>
    public static class CloudSqlProxyServiceCollectionExtensions
    {
        /// <summary>
        /// Registers a Cloud SQL Proxy instance as a singleton in the dependency injection container.
        /// </summary>
        /// <param name="services"></param>
        /// <param name="authenticationMethod">authentication method</param>
        /// <param name="instance">instance</param>
        /// <param name="credentials">credential file or json</param>
        /// <returns>The same service collection so that multiple calls can be chained.</returns>
        public static IServiceCollection AddCloudSqlProxy(
            this IServiceCollection services,
            AuthenticationMethod authenticationMethod,
            string instance,
            string credentials)
            => services.AddSingleton(provider
                => ProxyInstance.StartProxy(authenticationMethod, instance, credentials));

        /// <summary>
        /// Registers a Cloud SQL Proxy instance as a singleton in the dependency injection container.
        /// </summary>
        /// <param name="services">The service collection to add the proxy to.</param>
        /// <param name="instance">Cloud SQL instance connection name.</param>
        /// <param name="accessTokenSource">Source for Google Cloud access tokens. The source instance is used as the proxy reuse identity.</param>
        /// <returns>The same service collection so that multiple calls can be chained.</returns>
        public static IServiceCollection AddCloudSqlProxy(
            this IServiceCollection services,
            string instance,
            IAccessTokenSource accessTokenSource)
            => services.AddSingleton(provider
                => ProxyInstance.StartProxy(instance, accessTokenSource));
    }
}
