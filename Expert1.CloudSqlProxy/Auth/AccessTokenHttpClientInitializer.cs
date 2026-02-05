using Google.Apis.Http;

namespace Expert1.CloudSqlProxy.Auth;
internal sealed class AccessTokenHttpClientInitializer : IConfigurableHttpClientInitializer
{
    private readonly AccessTokenInterceptor _interceptor;

    public AccessTokenHttpClientInitializer(IAccessTokenSource source)
        => _interceptor = new AccessTokenInterceptor(source);

    public void Initialize(ConfigurableHttpClient httpClient)
    {
        // Attach interceptor for every request
        httpClient.MessageHandler.Credential = _interceptor;

        // Optional knobs (these *do* exist):
        // httpClient.MessageHandler.NumTries = 3;
        // httpClient.MessageHandler.FollowRedirect = true;
        // httpClient.MessageHandler.ApplicationName = "Expert1.CloudSqlProxy";
    }
}