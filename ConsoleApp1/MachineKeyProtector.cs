﻿using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    public class MachineKeyProtector : IDataProtector
    {
        private readonly string[] _purpose =
        {
            typeof(OAuthAuthorizationServerMiddleware).Namespace,
            "Access_Token",
            "v1"
        };

        public byte[] Protect(byte[] userData)
        {
            return System.Web.Security.MachineKey.Protect(userData, _purpose);
        }

        public byte[] Unprotect(byte[] protectedData)
        {
            return System.Web.Security.MachineKey.Unprotect(protectedData, _purpose);
        }
    }
}
