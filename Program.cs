using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;
using System.Threading.RateLimiting;
using System.Net;
using Npgsql;
var builder=WebApplication.CreateBuilder(args);
string Required(string key)=>Environment.GetEnvironmentVariable(key) is string value&&!string.IsNullOrWhiteSpace(value)?value:throw new InvalidOperationException("Missing server setting: "+key);
var publicUrl=new Uri(Required("OBLIK_PUBLIC_URL"));if(publicUrl.Scheme!="https"||publicUrl.AbsolutePath!="/"||publicUrl.Query!=""||publicUrl.Fragment!=""||publicUrl.UserInfo!="")throw new InvalidOperationException("OBLIK_PUBLIC_URL must be an HTTPS origin.");
var db=new NpgsqlConnectionStringBuilder(Required("OBLIK_DATABASE")){SslMode=SslMode.VerifyFull,ApplicationName="OblikPortal"};PortalDb.Connection=db.ConnectionString;
Totp.Key=Convert.FromBase64String(Required("OBLIK_MFA_KEY"));if(Totp.Key.Length!=32)throw new InvalidOperationException("MFA key must contain 32 random bytes.");
builder.Services.AddAntiforgery(o=>{o.HeaderName="X-CSRF-TOKEN";o.Cookie.Name="__Host-oblik-csrf";o.Cookie.SecurePolicy=CookieSecurePolicy.Always;o.Cookie.SameSite=SameSiteMode.Strict;o.Cookie.HttpOnly=true;o.Cookie.Path="/";});
builder.Services.AddRateLimiter(o=>{o.RejectionStatusCode=429;o.GlobalLimiter=PartitionedRateLimiter.Create<HttpContext,string>(ctx=>RateLimitPartition.GetFixedWindowLimiter(ctx.Connection.RemoteIpAddress?.ToString()??"unknown",_=>new FixedWindowRateLimiterOptions{PermitLimit=90,Window=TimeSpan.FromMinutes(1),QueueLimit=0}));});
var proxy=Environment.GetEnvironmentVariable("OBLIK_TRUSTED_PROXY");
if(!string.IsNullOrWhiteSpace(proxy))builder.Services.Configure<ForwardedHeadersOptions>(o=>{o.ForwardedHeaders=ForwardedHeaders.XForwardedFor|ForwardedHeaders.XForwardedProto;o.ForwardLimit=1;o.KnownProxies.Clear();o.KnownIPNetworks.Clear();o.KnownProxies.Add(IPAddress.Parse(proxy));});
builder.WebHost.ConfigureKestrel(o=>o.Limits.MaxRequestBodySize=16384);
var app=builder.Build();if(!string.IsNullOrWhiteSpace(proxy))app.UseForwardedHeaders();app.UseRateLimiter();
app.Use(async(context,next)=>
{
    context.Response.Headers.CacheControl="no-store";context.Response.Headers["X-Content-Type-Options"]="nosniff";context.Response.Headers["X-Frame-Options"]="DENY";context.Response.Headers["Referrer-Policy"]="no-referrer";context.Response.Headers["X-Robots-Tag"]="noindex, nofollow, noarchive";context.Response.Headers["Content-Security-Policy"]="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    if(!context.Request.IsHttps||!string.Equals(context.Request.Host.Value,publicUrl.Authority,StringComparison.OrdinalIgnoreCase)){context.Response.StatusCode=400;return;}
    context.Response.Headers["Strict-Transport-Security"]="max-age=31536000";
    try
    {
        if(HttpMethods.IsPost(context.Request.Method))
        {
            if(context.Request.Headers.Origin.ToString()!=publicUrl.GetLeftPart(UriPartial.Authority)){context.Response.StatusCode=403;return;}
            await context.RequestServices.GetRequiredService<IAntiforgery>().ValidateRequestAsync(context);
        }
        await next();
    }
    catch(UnauthorizedAccessException)
    {
        try{PortalDb.Audit(context,context.Items["attemptedUser"] as string??"Непідтверджений користувач",context.Request.Path.ToString(),false);}catch{ /* Access remains denied when audit storage is unavailable. */ }context.Response.StatusCode=401;await context.Response.WriteAsJsonAsync(new{error="Вхід не підтверджено або немає доступу. Перевірте пароль, новий код автентифікатора та запрошення для першого входу."});
    }
    catch(AntiforgeryValidationException){context.Response.StatusCode=403;await context.Response.WriteAsJsonAsync(new{error="Оновіть сторінку та повторіть дію."});}
    catch(Exception){context.Response.StatusCode=503;await context.Response.WriteAsJsonAsync(new{error="Сервіс тимчасово недоступний. Повторіть пізніше."});}
});
app.MapGet("/api/csrf",(HttpContext c,IAntiforgery csrf)=>Results.Json(new{token=csrf.GetAndStoreTokens(c).RequestToken}));
app.MapPost("/api/login",(HttpContext c,LoginInput input)=>{c.Items["attemptedUser"]=(input.Username??"")[..Math.Min((input.Username??"").Length,150)];return PortalAuth.Login(c,input);});
app.MapPost("/api/enroll",(HttpContext c,EnrollInput input)=>PortalAuth.Enroll(c,input));
app.MapPost("/api/logout",(HttpContext c)=>PortalAuth.Logout(c));
app.MapGet("/api/filters",(HttpContext c)=>Results.Json(PortalData.Filters(c,PortalAuth.Require(c))));
app.MapGet("/api/items",(HttpContext c,int org,int warehouse,bool future,string? search,int page)=>Results.Json(PortalData.Items(c,PortalAuth.Require(c),org,warehouse,future,search??"",page)));
app.UseDefaultFiles();app.UseStaticFiles();app.Run();
