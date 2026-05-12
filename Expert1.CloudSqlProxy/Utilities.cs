using System;
using System.IO;
using System.Text.Json;
using Google.Apis.Auth.OAuth2;
using Google.Apis.SQLAdmin.v1beta4;

namespace Expert1.CloudSqlProxy
{
    internal static class Utilities
    {
        private static string _userAgent;
        public static string UserAgent
        {
            get
            {
                if (string.IsNullOrWhiteSpace(_userAgent))
                {
                    _userAgent = $"Expert1.CloudSqlProxy/{GetVersion()}";
                }

                return _userAgent;
            }
        }

        private static string GetVersion() => typeof(ProxyInstance).Assembly.GetName().Version.ToString(3);

        public static (string project, string region, string name) SplitName(string instance)
        {
            ReadOnlySpan<char> span = instance.AsSpan();
            int firstColon = span.IndexOf(':');
            if (firstColon == -1)
            {
                return ("", "", instance);
            }

            int secondColon = span[(firstColon + 1)..].IndexOf(':');
            if (secondColon != -1)
            {
                secondColon += firstColon + 1;
            }

            int dotIndex = span[..firstColon].IndexOf('.');

            if (dotIndex != -1 && secondColon != -1)
            {
                // Handle case where first segment contains a dot and there are two colons
                string project = new(span[..secondColon]);
                int thirdColon = span[(secondColon + 1)..].IndexOf(':');
                if (thirdColon != -1)
                {
                    thirdColon += secondColon + 1;
                    string region = new(span.Slice(secondColon + 1, thirdColon - secondColon - 1));
                    string name = new(span[(thirdColon + 1)..]);
                    return (project, region, name);
                }
                else
                {
                    string region = new(span[(secondColon + 1)..]);
                    return (project, region, "");
                }
            }
            else if (secondColon == -1)
            {
                string project = new(span[..firstColon]);
                string name = new(span[(firstColon + 1)..]);
                return (project, "", name);
            }
            else
            {
                string project = new(span[..firstColon]);
                string region = new(span.Slice(firstColon + 1, secondColon - firstColon - 1));
                string name = new(span[(secondColon + 1)..]);
                return (project, region, name);
            }
        }

        public static string NormalizeInstanceName(string instance)
        {
            var (project, region, instanceId) = SplitName(instance);

            // canonical internal format
            return $"{project}:{region}:{instanceId}";
        }

        public static GoogleCredential CreateGoogleCredential(
            AuthenticationMethod authenticationMethod,
            string credentials)
        {
            if (credentials is null)
                throw new ArgumentNullException(nameof(credentials));

            string json = authenticationMethod == AuthenticationMethod.CredentialFile
                ? File.ReadAllText(credentials)
                : credentials;

            using JsonDocument document = JsonDocument.Parse(json);
            if (!document.RootElement.TryGetProperty("type", out JsonElement typeElement))
                throw new InvalidOperationException("Google credential JSON does not contain a credential type.");

            string type = typeElement.GetString();
            GoogleCredential credential = type switch
            {
                string value when string.Equals(value, "service_account", StringComparison.OrdinalIgnoreCase) =>
                    CredentialFactory.FromJson<ServiceAccountCredential>(json).ToGoogleCredential(),

                string value when string.Equals(value, "authorized_user", StringComparison.OrdinalIgnoreCase) =>
                    CredentialFactory.FromJson<UserCredential>(json).ToGoogleCredential(),

                string value when string.Equals(value, "external_account_authorized_user", StringComparison.OrdinalIgnoreCase) =>
                    CredentialFactory.FromJson<ExternalAccountAuthorizedUserCredential>(json).ToGoogleCredential(),

                string value when string.Equals(value, "impersonated_service_account", StringComparison.OrdinalIgnoreCase) =>
                    CredentialFactory.FromJson<ImpersonatedCredential>(json).ToGoogleCredential(),

                string value when string.Equals(value, "external_account", StringComparison.OrdinalIgnoreCase) =>
                    CreateExternalAccountCredential(json, document.RootElement),

                _ => throw new InvalidOperationException($"Unsupported Google credential type '{type}'.")
            };

            return credential.CreateScoped(SQLAdminService.Scope.CloudPlatform);
        }

        private static GoogleCredential CreateExternalAccountCredential(
            string json,
            JsonElement rootElement)
        {
            if (!rootElement.TryGetProperty("credential_source", out JsonElement credentialSource))
                throw new InvalidOperationException("External account credential JSON does not contain a credential_source.");

            if (credentialSource.TryGetProperty("environment_id", out _))
                return CredentialFactory.FromJson<AwsExternalAccountCredential>(json).ToGoogleCredential();

            if (credentialSource.TryGetProperty("file", out _))
                return CredentialFactory.FromJson<FileSourcedExternalAccountCredential>(json).ToGoogleCredential();

            if (credentialSource.TryGetProperty("url", out _))
                return CredentialFactory.FromJson<UrlSourcedExternalAccountCredential>(json).ToGoogleCredential();

            throw new InvalidOperationException("Unsupported external account credential_source.");
        }
    }
}
