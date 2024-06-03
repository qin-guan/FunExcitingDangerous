using System.Text;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateSlimBuilder(args);

builder.Services.AddHttpClient();
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
});

builder.Services.AddOptions<AuthenticationOptions>()
    .Bind(builder.Configuration.GetSection("Authentication"));

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

builder.Services.AddHealthChecks();

var app = builder.Build();

app.UseMiddleware<AuthMiddleware>();

var internalGroup = app.MapGroup("/__internal");
internalGroup.MapHealthChecks("/healthz");
internalGroup.MapGet("/ipinfo", (HttpClient httpClient) =>
    httpClient.GetFromJsonAsync<IpInfoResponse>(
        "https://ipinfo.io",
        AppJsonSerializerContext.Default.IpInfoResponse
    )
);

app.MapReverseProxy();

app.Run();

public class AuthMiddleware(RequestDelegate next, IOptions<AuthenticationOptions> options)
{
    public Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Headers.TryGetValue("Authorization", out var auth))
        {
            context.Response.StatusCode = 403;
            return Task.CompletedTask;
        }

        var credentials = auth
            .Where(v => v != null && v.StartsWith("Basic "))
            .Select(v => v?.Replace("Basic ", ""));

        var hasValidCredential = credentials.Any(s =>
        {
            try
            {
                var credential = Encoding.UTF8.GetString(Convert.FromBase64String(s!)).Split(":");
                if (credential.Length != 2) return false;
                return credential[0] == options.Value.Username && credential[1] == options.Value.Password;
            }
            catch
            {
                return false;
            }
        });

        if (hasValidCredential) return next(context);

        context.Response.StatusCode = 401;

        return Task.CompletedTask;
    }
}

public class AuthenticationOptions
{
    public string Username { get; set; } = "funexcitingdangerous";
    public string Password { get; set; } = "funexcitingdangerous";
};

public record IpInfoResponse([property: JsonPropertyName("ip")] string Ip);

[JsonSerializable(typeof(IpInfoResponse))]
internal partial class AppJsonSerializerContext : JsonSerializerContext;