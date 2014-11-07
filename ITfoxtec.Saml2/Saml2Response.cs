using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IdentityModel.Protocols.WSTrust;
using System.Linq;
using System.Security.Claims;
using System.ServiceModel;
using System.Xml;
using System.IdentityModel.Tokens;
using System.Xml.Linq;
using ITfoxtec.Saml2.Util;
using ITfoxtec.Saml2.Extensions;
using ITfoxtec.Saml2.Schemas;
using ITfoxtec.Saml2.Cryptography;

namespace ITfoxtec.Saml2
{
    /// <summary>
    /// Generic Saml2 Response.
    /// </summary>
    public abstract class Saml2Response : Saml2Request
    {
        /// <summary>
        /// [Required]
        /// A code representing the status of the corresponding request.
        /// </summary>
        public Saml2StatusCodes Status { get; set; }


        protected override IEnumerable<XObject> GetXContent()
        {
            foreach (var item in  base.GetXContent())
            {
                yield return item;
            }

            yield return new XElement(Saml2Constants.ProtocolNamespaceX + Saml2Constants.Message.Status, 
                new XElement(Saml2Constants.ProtocolNamespaceX + Saml2Constants.Message.StatusCode, 
                    new XAttribute(Saml2Constants.Message.Value, Saml2StatusCodeUtil.ToString(Status))));
        }

        internal override void Read(string xml, bool validateXmlSignature = false)
        {
            base.Read(xml, validateXmlSignature);

            Status = Saml2StatusCodeUtil.ToEnum(XmlDocument.DocumentElement[Saml2Constants.Message.Status, Saml2Constants.ProtocolNamespace.OriginalString][Saml2Constants.Message.StatusCode, Saml2Constants.ProtocolNamespace.OriginalString].Attributes[Saml2Constants.Message.Value].GetValueOrNull());

            DecryptMessage();

            if (validateXmlSignature)
            {
                ValidateXmlSignature();
            }
        }

        protected abstract void DecryptMessage();

        private void ValidateXmlSignature()
        {
            var signedXml = new Saml2SignedXml(XmlDocument);

            var xmlSignatures = XmlDocument.DocumentElement.GetElementsByTagName(Saml2Constants.Message.Signature, Saml2SignedXml.XmlDsigNamespaceUrl);
            if (xmlSignatures.Count == 0)
            {
                throw new Saml2ResponseException("Signature Not Found. Maybe the response is encrypted.");
            }
            else
            {
                signedXml.LoadXml(xmlSignatures[0] as XmlElement);
                if (!signedXml.CheckSignature(SignatureValidationCertificate))
                {
                    throw new Saml2ResponseException("Signature is invalid.");
                }
            }
        }

    }
}
