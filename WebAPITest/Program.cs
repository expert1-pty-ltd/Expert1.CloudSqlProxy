using Expert1.CloudSqlProxy;
using Microsoft.Data.SqlClient;
using WebAPITest;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();
IConfigurationSection appSettingsSection = builder.Configuration.GetSection(nameof(AppSettings));
AppSettings appSettings = appSettingsSection.Get<AppSettings>()!;

builder.Services.AddCloudSqlProxy(
    AuthenticationMethod.CredentialFile,
    appSettings.Instance,
    appSettings.AuthFileLocation);

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}


SqlConnectionStringBuilder connectionStringBuilder = new(builder.Configuration.GetConnectionString("DefaultConnection"))
{
    DataSource = app.Services.GetRequiredService<ProxyInstance>().DataSource,
};

app.UseHttpsRedirection();

app.MapGet("/test", async () =>
{
    using (var connection = new SqlConnection(connectionStringBuilder.ConnectionString))
    {
        await connection.OpenAsync();
        using (var command = new SqlCommand("SELECT TOP 1 name FROM sys.databases", connection))
        {
            return await command.ExecuteScalarAsync();
        }
    }
})
.WithName("test");

app.Run();
