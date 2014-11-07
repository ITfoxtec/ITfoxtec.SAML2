using ITfoxtec.Saml2;
using ITfoxtec.Saml2.Bindings;
using ITfoxtec.Saml2.Util;
using ITfoxtec.Saml2.Mvc;
using System;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.Linq;
using System.Security.Claims;
using System.ServiceModel;
using System.Web;
using System.Web.Mvc;

namespace WebAppTest.Controllers
{
    public class IdPInitiatedController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Initiate()
        {
            var serviceProviderRealm = "https://webapptest.somedomain.com";

            var binding = new Saml2PostBinding();
            binding.RelayState = string.Format("{0}={1}", "RPID", HttpUtility.UrlEncode(serviceProviderRealm));

            var response = new Saml2IdPInitiatedAuthnResponse
            {
                Issuer = new EndpointReference("http://udv.itfoxtec.com/webapptest"),
                Destination = new EndpointAddress("https://udv.itfoxtec.com/adfs/ls/"),
            };
            response.ClaimsIdentity = new ClaimsIdentity(CreateClaims());
            response.CreateSecurityToken(CertificateUtil.Load("~/App_Data/webapptest_certificate.pfx"));

            return binding.Bind(response).ToActionResult();
        }

        private IEnumerable<Claim> CreateClaims()
        {
            yield return new Claim(ClaimTypes.NameIdentifier, "someuseridentity");
            yield return new Claim(ClaimTypes.Email, "someuser@domain.com");
        } 

    }
}