using ITfoxtec.Saml2;
using ITfoxtec.Saml2.Bindings;
using ITfoxtec.Saml2.Mvc;
using ITfoxtec.Saml2.Schemas;
using ITfoxtec.Saml2.Util;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Protocols.WSTrust;
using System.ServiceModel;
using System.Web.Mvc;

namespace WebAppTest.Controllers
{
    [AllowAnonymous]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";

        public ActionResult Login(string returnUrl)
        {
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl } });

            return binding.Bind(new Saml2AuthnRequest
            {
                //ForceAuthn = true,
                //NameIdPolicy = new NameIdPolicy { AllowCreate = true, Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" },
                RequestedAuthnContext = new RequestedAuthnContext
                {
                    Comparison = AuthnContextComparisonTypes.Exact,
                    AuthnContextClassRef = new string[] { AuthnContextClassTypes.PasswordProtectedTransport.OriginalString },
                },
                Issuer = new EndpointReference("http://udv.itfoxtec.com/webapptest"),
                Destination = new EndpointAddress("https://udv.itfoxtec.com/adfs/ls/"),
                AssertionConsumerServiceUrl = new EndpointAddress("https://udv.itfoxtec.com/webapptest/Auth/AssertionConsumerService")
            }).ToActionResult();
        }

        public ActionResult AssertionConsumerService()
        {
            var binding = new Saml2PostBinding();
            var saml2AuthnResponse = new Saml2AuthnResponse();

            binding.Unbind(Request, saml2AuthnResponse, CertificateUtil.Load("~/App_Data/signing-adfs.test_Certificate.crt"));
            saml2AuthnResponse.CreateSession();

            var returnUrl = binding.GetRelayStateQuery()[relayStateReturnUrl];
            return Redirect(string.IsNullOrWhiteSpace(returnUrl) ? Url.Content("~/") : returnUrl);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Logout()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Content("~/"));
            }

            var binding = new Saml2PostBinding();
            return binding.Bind(new Saml2LogoutRequest
            {
                Issuer = new EndpointReference("http://udv.itfoxtec.com/webapptest"),
                Destination = new EndpointAddress("https://udv.itfoxtec.com/adfs/ls/")
            }, CertificateUtil.Load("~/App_Data/webapptest_certificate.pfx")).ToActionResult();
        }

        public ActionResult LoggedOut()
        {
            var binding = new Saml2RedirectBinding();
            binding.Unbind(Request, new Saml2LogoutResponse(), CertificateUtil.Load("~/App_Data/signing-adfs.test_Certificate.crt")).DeleteSession();

            return Redirect(Url.Content("~/"));
        }

        public ActionResult SingleLogout()
        {
            Saml2StatusCodes status;
            var requestBinding = new Saml2RedirectBinding();
            var logoutRequest = new Saml2LogoutRequest();
            try
            {
                requestBinding.Unbind(Request, logoutRequest, CertificateUtil.Load("~/App_Data/signing-adfs.test_Certificate.crt"));
                status = Saml2StatusCodes.Success;
            }
            catch (Exception exc)
            {
                // log exception
                Debug.WriteLine("SingleLogout error: " + exc.ToString());
                status = Saml2StatusCodes.RequestDenied;
            }

            var responsebinding = new Saml2RedirectBinding();
            responsebinding.RelayState = requestBinding.RelayState;
            var saml2LogoutResponse = new Saml2LogoutResponse
            {
                InResponseTo = logoutRequest.Id,
                Status = status,
                Issuer = new EndpointReference("http://udv.itfoxtec.com/webapptest"),
                Destination = new EndpointAddress("https://udv.itfoxtec.com/adfs/ls/")
            };
            saml2LogoutResponse.DeleteSession();
            return responsebinding.Bind(saml2LogoutResponse, CertificateUtil.Load("~/App_Data/webapptest_certificate.pfx")).ToActionResult();
        }
    }
}