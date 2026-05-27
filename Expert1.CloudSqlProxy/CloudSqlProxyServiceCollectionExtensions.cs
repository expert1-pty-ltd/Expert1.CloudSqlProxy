using Expert1.CloudSqlProxy.Auth;
using Google.Apis.Auth.OAuth2;
using Microsoft.Extensions.DependencyInjection;
using System;

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
        {
            ArgumentNullException.ThrowIfNull(services);
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(credentials);

            return services.AddSingleton(provider
                => ProxyInstance.StartProxy(authenticationMethod, instance, credentials));
        }

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
        {
            ArgumentNullException.ThrowIfNull(services);
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(accessTokenSource);

            return services.AddSingleton(provider
                => ProxyInstance.StartProxy(instance, accessTokenSource));
        }

        /// <summary>
        /// Registers a Cloud SQL Proxy instance as a singleton in the dependency injection container.
        /// Reuse the same <see cref="GoogleCredential"/> instance to reuse the same shared proxy.
        /// </summary>
        /// <param name="services">The service collection to add the proxy to.</param>
        /// <param name="instance">Cloud SQL instance connection name.</param>
        /// <param name="credential">Google credential to use for Cloud SQL Admin API calls.</param>
        /// <returns>The same service collection so that multiple calls can be chained.</returns>
        public static IServiceCollection AddCloudSqlProxy(
            this IServiceCollection services,
            string instance,
            GoogleCredential credential)
        {
            ArgumentNullException.ThrowIfNull(services);
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(credential);

            return services.AddSingleton(provider
                => ProxyInstance.StartProxy(instance, credential));
        }
    }
}
