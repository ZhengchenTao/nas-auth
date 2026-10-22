using Microsoft.AspNetCore.Http;
using NasAuth.Pages;

namespace NasAuth.Services;

/// <summary>
/// Makes the public mount prefix available to SSR helpers and fixes local Location headers.
/// The protected-site callbacks are excluded: they arrive through the internal PathBase, but
/// their redirects target the protected site's own path space.
/// </summary>
public static class PathBaseUrlMiddleware
{
    public static async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var previous = Ui.PathBase;
        var prefix = context.Request.PathBase.Value ?? "";
        var isProtectedSiteCallback = context.Request.Path.StartsWithSegments(ForwardAuthService.PathPrefix);
        Ui.PathBase = prefix;

        if (prefix.Length > 0 && !isProtectedSiteCallback)
        {
            context.Response.OnStarting(() =>
            {
                PrefixLocation(context, prefix);
                return Task.CompletedTask;
            });
        }

        try
        {
            await next(context);
            if (!context.Response.HasStarted && prefix.Length > 0 && !isProtectedSiteCallback)
                PrefixLocation(context, prefix);
        }
        finally
        {
            Ui.PathBase = previous;
        }
    }

    private static void PrefixLocation(HttpContext context, string prefix)
    {
        var location = context.Response.Headers.Location.ToString();
        if (location.StartsWith('/') && !location.StartsWith("//", StringComparison.Ordinal) &&
            !IsAtOrBelowPrefix(location, prefix))
            context.Response.Headers.Location = prefix + location;
    }

    private static bool IsAtOrBelowPrefix(string pathOrUrl, string prefix)
    {
        var end = pathOrUrl.IndexOfAny(['?', '#']);
        var path = end < 0 ? pathOrUrl : pathOrUrl[..end];
        return path.Equals(prefix, StringComparison.Ordinal) ||
               path.StartsWith(prefix + "/", StringComparison.Ordinal);
    }
}
