using ITfoxtec.Saml2;
using ITfoxtec.Saml2.Schemas;
using ITfoxtec.Saml2.Schemas.Metadata;
using ITfoxtec.Saml2.Util;
using ITfoxtec.Saml2.Mvc;
using System.ServiceModel;
using System.Web.Mvc;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;

namespace WebAppTest.Controllers
{
    public class MetadataController : Controller
    {
        public ActionResult Index()
        {
            var entityDescriptor = new EntityDescriptor(new EndpointReference("http://udv.itfoxtec.com/webapptest"), CertificateUtil.Load("~/App_Data/webapptest_certificate.pfx"));
            entityDescriptor.ValidUntil = 365;
            //entityDescriptor.SPSsoDescriptor = new SPSsoDescriptor(CertificateUtil.Load("~/App_Data/webapptest_certificate.pfx"), CertificateUtil.Load("~/App_Data/webapptest_encryptioncertificate.pfx")) 
            entityDescriptor.SPSsoDescriptor = new SPSsoDescriptor(CertificateUtil.Load("~/App_Data/webapptest_certificate.pfx")) 
            {
                WantAssertionsSigned = true,
                SingleLogoutService = new SingleLogoutService(ProtocolBindings.HttpRedirect, new EndpointAddress("https://udv.itfoxtec.com/webapptest/Auth/SingleLogout"), new EndpointAddress("https://udv.itfoxtec.com/webapptest/LoggedOut")),
                NameIDFormat = NameIdentifierFormats.X509SubjectName,
                AssertionConsumerService = new AssertionConsumerService(ProtocolBindings.HttpPost, new EndpointAddress("https://udv.itfoxtec.com/webapptest/Auth/AssertionConsumerService")),
                AttributeConsumingService = new AttributeConsumingService(new ServiceName("Some SP", "da"), CreateRequestedAttributes()),
            };
            entityDescriptor.ContactPerson = new ContactPerson(ContactTypes.Administrative)
            {
                Company = "Some Company",
                GivenName = "Some Given Name",
                SurName = "Some Sur Name",
                EmailAddress = "some@somedomain.com",
                TelephoneNumber = "11111111",
            };
            return new Saml2Metadata(entityDescriptor).CreateMetadata().ToActionResult();
        }

        private IEnumerable<RequestedAttribute> CreateRequestedAttributes()
        {
            yield return new RequestedAttribute("urn:oid:2.5.4.4");
            yield return new RequestedAttribute("urn:oid:2.5.4.3", false);
        }   

    }
}