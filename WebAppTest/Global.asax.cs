using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace WebAppTest
{
    using System.IdentityModel.Tokens;
    using System.Security.Cryptography;
    using ITfoxtec.Saml2.Cryptography;

    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            IdentityConfig.RegisterIdentity();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);

            // Enable SHA-1 XML CNG signature support.
            CryptoConfig.AddAlgorithm(
                typeof(RSAPKCS1SHA1SignatureDescription),
                SecurityAlgorithms.RsaSha1Signature);

            // Enable SHA-256 XML CNG signature support.
            CryptoConfig.AddAlgorithm(
                typeof(RSAPKCS1SHA256SignatureDescription),
                SecurityAlgorithms.RsaSha256Signature);
        }
    }
}
