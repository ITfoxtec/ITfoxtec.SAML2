using ITfoxtec.Saml2.Schemas;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Saml2
{
    /// <summary>
    /// Saml2 Logout Response.
    /// </summary>
    public class Saml2LogoutResponse : Saml2Response
    {
        const string elementName = Saml2Constants.Message.LogoutResponse;

        /// <summary>
        /// [Optional]
        /// A reference to the identifier of the request to which the response corresponds, if any. If the response
        /// is not generated in response to a request, or if the ID attribute value of a request cannot be
        /// determined (for example, the request is malformed), then this attribute MUST NOT be present.
        /// Otherwise, it MUST
        /// </summary>
        public Saml2Id InResponseTo { get; set; }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != elementName)
            {
                throw new Saml2ResponseException("Not a SAML2 Logout Response.");
            }
        }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(Saml2Constants.ProtocolNamespaceX + elementName);

            envelope.Add(base.GetXContent());
            envelope.Add(GetXContent());

            XmlDocument = envelope.ToXmlDocument();
            return XmlDocument;
        }

        protected override IEnumerable<XObject> GetXContent()
        {
            if (InResponseTo != null)
            {
                yield return new XAttribute(Saml2Constants.Message.InResponseTo, InResponseTo);
            }
        }

        protected override void DecryptMessage()
        { }
    }
}
