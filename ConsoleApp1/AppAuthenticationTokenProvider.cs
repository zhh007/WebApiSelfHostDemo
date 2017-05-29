using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataHandler.Serializer;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    public class AppAuthenticationTokenProvider : AuthenticationTokenProvider
    {
        public override void Create(AuthenticationTokenCreateContext context)
        {
            //var ticket = context.Ticket;
            //var ticketSerializer = new TicketSerializer();         // Add
            //var ticketBytes = ticketSerializer.Serialize(ticket);  // Add

            //System.Security.Cryptography.DpapiDataProtector.Protect(ticketBytes);

            base.Create(context);
        }

        public override Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            return base.CreateAsync(context);
        }

        public override void Receive(AuthenticationTokenReceiveContext context)
        {
            base.Receive(context);
        }

        public override Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            var access_token = context.Token;

        //    IDataProtector dataProtecter = app.CreateDataProtector(
        //typeof(OAuthAuthorizationServerMiddleware).Namespace,
        //"Access_Token", "v1");
            //var secureDataFormat = new TicketDataFormat(new MachineKeyProtector());
            //AuthenticationTicket ticket = secureDataFormat.Unprotect(access_token);

            //context.DeserializeTicket(context.Token);
            return base.ReceiveAsync(context);
        }
    }
}
