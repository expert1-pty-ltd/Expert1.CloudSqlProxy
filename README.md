# Cloud SQL Proxy

This project provides a .NET library for creating and managing secure connections to Google Cloud SQL instances using a local proxy. The proxy establishes an SSL/TLS connection to the Cloud SQL instance, allowing local applications to communicate with the database securely.

## Features

- Secure connection to Google Cloud SQL instances
- Automatic SSL/TLS certificate management
- Supports multiple concurrent connections
- Handles periodic certificate refresh

## Prerequisites

- .NET 8 or .NET 9
- Google Cloud SDK
- Google Cloud SQL instance

## Installation

To install the library, add it to your project via NuGet Package Manager:

PM> Install-Package Expert1.CloudSqlProxy

## Usage

### Authentication

The proxy supports these authentication methods:

1. **Credential File**: Path to the Google credentials JSON file.
2. **JSON String**: Google credentials JSON file content as a string.
3. **Access Token Source**: An `IAccessTokenSource` implementation that supplies Google API access tokens.

### Creating a Proxy Instance

To create and start a proxy instance, use the `ProxyInstance.StartProxyAsync` method. You can provide the authentication method, instance connection string, and credentials.

```csharp
using System;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        string instance = "your-project:your-region:your-instance-id";
        string credentialsPath = "path/to/your/credentials.json";
        
        try
        {
            using ProxyInstance proxyInstance = await ProxyInstance.StartProxyAsync(
                AuthenticationMethod.CredentialFile, 
                instance, 
                credentialsPath
            );

            Console.WriteLine($"Proxy started. Connect to your database using DataSource: {proxyInstance.DataSource}");
            
            // Use proxyInstance.DataSource to connect to your database.
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to start proxy: {ex.Message}");
        }
    }
}
```

### Using an Access Token Source

`IAccessTokenSource` can be used when your application manages Google API tokens itself, such as with workload identity or user pass-through.

```csharp
IAccessTokenSource tokenSource = GetTokenSourceForCurrentIdentity();
using ProxyInstance proxyInstance = await ProxyInstance.StartProxyAsync(
    "your-project:your-region:your-instance-id",
    tokenSource
);
```

Reuse the same token source instance for refreshed tokens that belong to the same identity. Use a different token source instance for each distinct user, tenant, or service identity.

### Dependency Injection

For applications using `Microsoft.Extensions.DependencyInjection`, register the proxy as a singleton:

```csharp
using Expert1.CloudSqlProxy;

builder.Services.AddCloudSqlProxy(
    AuthenticationMethod.CredentialFile,
    "your-project:your-region:your-instance-id",
    "path/to/your/credentials.json"
);
```

Or register a proxy with an access token source:

```csharp
using Expert1.CloudSqlProxy;
using Expert1.CloudSqlProxy.Auth;

IAccessTokenSource tokenSource = GetTokenSourceForCurrentIdentity();

builder.Services.AddCloudSqlProxy(
    "your-project:your-region:your-instance-id",
    tokenSource
);
```

The registered `ProxyInstance` can then be injected into services that need a database connection string:

```csharp
public sealed class MyRepository
{
    private readonly ProxyInstance proxyInstance;

    public MyRepository(ProxyInstance proxyInstance)
    {
        this.proxyInstance = proxyInstance;
    }

    public string DataSource => proxyInstance.DataSource;
}
```

The dependency injection container owns the singleton proxy and will dispose it when the service provider is disposed.

### Connecting to the Database

Once the proxy is started, you can connect to your Cloud SQL database using the `DataSource` property of the `ProxyInstance`. For SQL Server, this property provides the `127.0.0.1,<port>` value that can be used in your database connection string.

For example, to connect to a SQL Server instance:
```csharp
string connectionString = $"Server={proxyInstance.DataSource};Database=your-database;User Id=your-username;Password=your-password;";
using var connection = new SqlConnection(connectionString);
connection.Open();
// Perform database operations
```

### Proxy Reuse

Calls to `StartProxyAsync` may share a running proxy for the same Cloud SQL instance and authentication identity. Each call returns its own disposable `ProxyInstance` lease. Dispose each returned instance when the caller no longer needs the proxy.

```csharp
using ProxyInstance proxyInstance = await ProxyInstance.StartProxyAsync(
    AuthenticationMethod.CredentialFile,
    instance,
    credentialsPath
);

// Use proxyInstance.DataSource while this lease is active.
```

### Stopping the Proxy

Dispose the `ProxyInstance` returned by `StartProxyAsync` when the caller no longer needs it:

```csharp
proxyInstance.Dispose();
```

Or use a `using` statement so disposal happens automatically:

```csharp
using ProxyInstance proxyInstance = await ProxyInstance.StartProxyAsync(
    AuthenticationMethod.CredentialFile,
    instance,
    credentialsPath
);

// Use the proxy here.
```

### Stopping All Proxies

To stop all running proxies in the current process, use `ProxyInstance.StopAllInstances`:

```csharp
ProxyInstance.StopAllInstances();
```
