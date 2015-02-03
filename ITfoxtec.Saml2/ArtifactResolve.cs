using ITfoxtec.Saml2.Schemas;
using ITfoxtec.Saml2.Util;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Saml2
{
    public class ArtifactResolve : Saml2Request
    {
        const string elementName = Saml2Constants.Message.ArtifactResolve;

        public X509Certificate2 SigningCertificate { get; set; }
        public string Artifact { get; set; }

        public ArtifactResolve(X509Certificate2 signingCertificate = null)
        {
            this.SigningCertificate = signingCertificate;
        }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(Saml2Constants.ProtocolNamespaceX + elementName);

            envelope.Add(base.GetXContent());
            envelope.Add(GetXContent());

            XmlDocument = envelope.ToXmlDocument();
            if (SigningCertificate != null)
                XmlDocument = XmlDocument.SignDocument(SigningCertificate, X509IncludeOption.EndCertOnly, Id.Value, removeKeyInfo: true);
            return XmlDocument;
        }

        protected override IEnumerable<XObject> GetXContent()
        {

            yield return new XElement(Saml2Constants.ProtocolNamespaceX + Saml2Constants.Message.Artifact, Artifact);
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != elementName)
            {
                throw new Saml2ResponseException("Not a SAML2 Artifact Resolve Request.");
            }
        }

        public void Resolve(IdpSsoService artifactResolutionService, Saml2AuthnResponse authnResponse)
        {
            var xmlDoc = this.ToXml();

            var soapEnvelope = new SOAPEnvelope();
            soapEnvelope.Body = xmlDoc;

            xmlDoc = soapEnvelope.ToSoapXml();
            WebClient client = new WebClient();
            client.Encoding = Encoding.UTF8;
            client.Headers.Add(HttpRequestHeader.ContentType, "text/xml; charset=\"utf-8\"");
            client.Headers.Add(HttpRequestHeader.Accept, "text/xml");
            var result = client.UploadString(artifactResolutionService.Location, xmlDoc.OuterXml);

            soapEnvelope.FromSoapXml(result);

            var ares = new SamlArtifactResponse(authnResponse)
            {
                SignatureValidationCertificate = SignatureValidationCertificate
            };
            ares.Read(soapEnvelope.Body.OuterXml, SignatureValidationCertificate != null);


        }

    }
}
