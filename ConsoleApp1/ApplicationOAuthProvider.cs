using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System.Data;
using System.Data.SqlClient;
using System.Configuration;

namespace ConsoleApp1
{
    public class ApplicationOAuthProvider : OAuthAuthorizationServerProvider
    {
        private string ZDWP_ConnectionString = ConfigurationManager.ConnectionStrings["ZDWP"].ConnectionString;
        //private IOAuthClientService _clientService;
        //private IUserLoginService _userLoginService;
        //private object CookieAuthenticationDefaults;

        public ApplicationOAuthProvider()
        {
            //_clientService = clientService;
            //_userLoginService = userLoginService;
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            ////调用后台的登录服务验证用户名与密码
            //var user = _userLoginService.UserLogin(context.UserName, context.Password);
            //if (user == null)
            //{
            //    context.SetError("invalid_grant", "用户名或密码不正确。");
            //    return;
            //}

            //var oAuthIdentity = new ClaimsIdentity(context.Options.AuthenticationType);
            //oAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, user.Name));
            //oAuthIdentity.AddClaim(new Claim(ClaimTypes.Sid, user.Code.ToString()));

            //ClaimsIdentity cookiesIdentity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationType);
            //cookiesIdentity.AddClaim(new Claim(ClaimTypes.Name, user.Name));
            //cookiesIdentity.AddClaim(new Claim(ClaimTypes.Sid, user.Code.ToString()));

            //var props = new AuthenticationProperties(new Dictionary<string, string>
            //    {
            //        {
            //            "as:client_id", (context.ClientId == null) ? string.Empty : context.ClientId
            //        },
            //        {
            //            "userName", context.UserName
            //        }
            //    });

            //var ticket = new AuthenticationTicket(oAuthIdentity, props);
            //context.Validated(ticket);

            ////开启可以登陆后台系统
            //context.Request.Context.Authentication.SignIn(cookiesIdentity);

            await base.GrantResourceOwnerCredentials(context);
        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId;
            string clientSecret;
            if (context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                var client = GetClientById(new Guid(clientId));
                if (client == null) { return Task.FromResult<object>(null); }
                if (client.Secret != clientSecret) { return Task.FromResult<object>(null); }

                context.OwinContext.Set<string>("as:client_id", clientId);
                context.OwinContext.Set<string>("as:clientRefreshTokenLifeTime", client.RefreshTokenLifeTime.ToString());

                context.Validated(clientId);
                return Task.FromResult<object>(null);
            }
            else
            {
                clientId = "self";
                context.OwinContext.Set<string>("as:client_id", clientId);
                //context.OwinContext.Set<string>("as:clientRefreshTokenLifeTime", client.RefreshTokenLifeTime.ToString());

                context.Validated(clientId);
                //context.Validated();
                return Task.FromResult<object>(null);
            }

            //if (context.ClientId == "self")
            //{
            //    Uri expectedRootUri = new Uri(context.Request.Uri, "/");

            //    if (expectedRootUri.AbsoluteUri == context.RedirectUri)
            //    {
            //        context.Validated();
            //    }
            //}

            return Task.FromResult<object>(null);
        }

        public override Task GrantClientCredentials(OAuthGrantClientCredentialsContext context)
        {
            var client = GetClientById(new Guid(context.ClientId));
            var oAuthIdentity = new ClaimsIdentity(context.Options.AuthenticationType);
            oAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, client.Name, ClaimValueTypes.String, "zdwp"));

            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    { "as:client_id", context.ClientId }
                });

            var ticket = new AuthenticationTicket(oAuthIdentity, props);
            context.Validated(ticket);

            return base.GrantClientCredentials(context);
        }

        public override Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            if (context.ClientId == "self")
            {
                Uri expectedRootUri = new Uri(context.Request.Uri, "/");

                if (expectedRootUri.AbsoluteUri == context.RedirectUri)
                {
                    context.Validated();
                }
            }

            return Task.FromResult<object>(null);
        }

        public override async Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originalClient = context.Ticket.Properties.Dictionary["as:client_id"];
            var currentClient = context.ClientId;

            if (originalClient != currentClient)
            {
                context.Rejected();
                return;
            }

            var newId = new ClaimsIdentity(context.Ticket.Identity);
            newId.AddClaim(new Claim("newClaim", "refreshToken"));

            var newTicket = new AuthenticationTicket(newId, context.Ticket.Properties);
            context.Validated(newTicket);

            await base.GrantRefreshToken(context);
        }

        private OAuthClient GetClientById(Guid id)
        {
            OAuthClient entity = null;
            string sql = @"
SELECT [Id]
      ,[Name]
      ,[Secret]
      ,[IsActive]
      ,[RefreshTokenLifeTime]
      ,[CreateTime]
  FROM [dbo].[OAuth_Client]
 WHERE [Id] = @Id
";

            using (SqlConnection conn = new SqlConnection(ZDWP_ConnectionString))
            {
                try
                {
                    SqlCommand cmd = new SqlCommand(sql, conn);

                    SqlParameter para_Id = new SqlParameter("Id", SqlDbType.UniqueIdentifier, 16);
                    para_Id.Value = id;
                    cmd.Parameters.Add(para_Id);

                    conn.Open();
                    using (SqlDataReader sdr = cmd.ExecuteReader())
                    {
                        if (sdr.Read())
                        {
                            entity = new OAuthClient();
                            entity.Id = (Guid)sdr["id"];
                            entity.Name = (string)sdr["name"];
                            entity.Secret = (string)sdr["secret"];
                            entity.IsActive = (bool)sdr["isactive"];
                            entity.RefreshTokenLifeTime = (int)sdr["refreshtokenlifetime"];
                            entity.CreateTime = (DateTime)sdr["createtime"];
                        }
                    }
                }
                finally
                {
                    if (conn.State != ConnectionState.Closed)
                        conn.Close();
                    if (conn != null)
                        conn.Dispose();
                }
            }

            return entity;
        }
    }

    public class OAuthClient
    {
        /// <summary>
        /// 
        /// </summary>
        public Guid Id { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public string Secret { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public bool IsActive { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public int RefreshTokenLifeTime { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public DateTime CreateTime { get; set; }
    }
}
