using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    public class AppOAuthBearerAuthenticationProvider : OAuthBearerAuthenticationProvider
    {
        private string ZDWP_ConnectionString = ConfigurationManager.ConnectionStrings["ZDWP"].ConnectionString;

        public override Task ValidateIdentity(OAuthValidateIdentityContext context)
        {
            var claims = context.Ticket.Identity.Claims;
            //if (claims.Count() == 0 || claims.Any(claim => claim.Issuer != "zdwp"))
            //    context.Rejected();

            if (!context.Ticket.Identity.IsAuthenticated)
            {
                context.Rejected();
            }

            var clientId = context.Ticket.Properties.Dictionary["as:client_id"];
            var client = GetClientById(new Guid(clientId));

            if(client == null)
            {
                context.Rejected();
            }

            return Task.FromResult<object>(null);
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

        public override Task RequestToken(OAuthRequestTokenContext context)
        {
            return base.RequestToken(context);
        }
    }
}
