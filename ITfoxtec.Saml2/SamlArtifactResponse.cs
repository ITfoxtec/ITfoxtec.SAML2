using ITfoxtec.Saml2.Schemas;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace ITfoxtec.Saml2
{
    public class SamlArtifactResponse : Saml2Response
    {
        const string elementName = Saml2Constants.Message.ArtifactResponse;
        internal X509Certificate2 DecryptionCertificate { get; private set; }

        public Saml2AuthnResponse AuthnResponse { get; set; }
        public SamlArtifactResponse(Saml2AuthnResponse response)
        {
            AuthnResponse = response;
        }

        protected override void DecryptMessage()
        {

        }

        internal override void Read(string xml, bool validateXmlSignature = false)
        {
            base.Read(xml, false);

            if (Status == Saml2StatusCodes.Success)
            {
                var authnReponse = GetAuthnReponse();
                AuthnResponse.Read(authnReponse.OuterXml, SignatureValidationCertificate != null && validateXmlSignature);
            }
        }

        private XmlNode GetAuthnReponse()
        {
            var assertionElements = XmlDocument.DocumentElement.SelectNodes(string.Format("//*[local-name()='{0}']", Saml2Constants.Message.AuthnResponse));
            if (assertionElements.Count != 1)
            {
                throw new Saml2ResponseException("There is not exactly one Assertion element.");
            }
            return assertionElements[0];
        }


        public override System.Xml.XmlDocument ToXml()
        {
            throw new NotImplementedException();
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != elementName)
            {
                throw new Saml2ResponseException("Not a SAML2 Artifact Response.");
            }
        }
    }
}
