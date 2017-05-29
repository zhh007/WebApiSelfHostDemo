using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Owin.Security;
using System.Web.Http.SelfHost;
using System.Web.Http;
using Microsoft.Owin.Security.DataHandler.Serializer;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.DataHandler;

[assembly: OwinStartup(typeof(ConsoleApp1.Startup))]
namespace ConsoleApp1
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            //var config = new HttpSelfHostConfiguration("http://localhost:9900");
            var config = new HttpConfiguration();

            config.SuppressDefaultHostAuthentication();
            config.Filters.Add(new HostAuthenticationFilter(OAuthDefaults.AuthenticationType));

            config.Routes.MapHttpRoute(
                "API Default", "api/{controller}/{action}/{id}",
                new { id = RouteParameter.Optional });

            //app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            //app.SetDefaultSignInAsAuthenticationType(DefaultAuthenticationTypes.)

            //app.UseCookieAuthentication(new CookieAuthenticationOptions
            //{
            //    AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
            //    LoginPath = new PathString("/Account/Login"),
            //    ExpireTimeSpan = TimeSpan.FromDays(7)
            //});

            // 针对基于 OAuth 的流配置应用程序
            //var PublicClientId = "self";
            var OAuthOptions = new OAuthAuthorizationServerOptions
            {
                TokenEndpointPath = new PathString("/Token"),
                Provider = new ApplicationOAuthProvider(),//PublicClientId
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(14),
                AllowInsecureHttp = true,
                //AccessTokenProvider = new AppAuthenticationTokenProvider()
                AccessTokenFormat = new SecureDataFormat<AuthenticationTicket>(DataSerializers.Ticket,
                    new MachineKeyProtector(), TextEncodings.Base64)
            };

            // 使应用程序可以使用不记名令牌来验证用户身份
            app.UseOAuthAuthorizationServer(OAuthOptions);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions()
            {
                Provider = new AppOAuthBearerAuthenticationProvider(),
                //AccessTokenProvider = new AppAuthenticationTokenProvider()
                AccessTokenFormat = new SecureDataFormat<AuthenticationTicket>(DataSerializers.Ticket,
                    new MachineKeyProtector(), TextEncodings.Base64)
            });

            app.UseWebApi(config);

            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
        }
    }
}
