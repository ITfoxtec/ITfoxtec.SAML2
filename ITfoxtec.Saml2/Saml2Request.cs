using ITfoxtec.Saml2.Extensions;
using ITfoxtec.Saml2.Schemas;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Saml2
{
    /// <summary>
    /// Generic Saml2 Request.
    /// </summary>
    public abstract class Saml2Request
    {
        public XmlDocument XmlDocument { get; protected set; }

        internal X509Certificate2 SignatureValidationCertificate { get; set; }

        public Saml2Request()
        {
            Id = new Saml2Id();
            Version = Saml2Constants.VersionNumber;
            IssueInstant = DateTime.UtcNow;
#if DEBUG
            Debug.WriteLine("Message ID: " + Id);
#endif

        }

        /// <summary>
        /// [Required]
        /// An identifier for the request. It is of type xs:ID and MUST follow the requirements specified in Section
        /// 1.3.4 for identifier uniqueness. The values of the ID attribute in a request and the InResponseTo
        /// attribute in the corresponding response MUST match.
        /// </summary>
        /// <value>The ID.</value>
        public Saml2Id Id { get; set; }

        /// <summary>
        /// [Required]
        /// The version of this request. The identifier for the version of SAML defined in this specification is "2.0".
        /// SAML versioning is discussed in Section 4.
        /// </summary>
        public string Version { get; set; }

        /// <summary>
        /// [Required]
        /// The time instant of issue of the request. The time value is encoded in UTC, as described in Section 1.3.3.
        /// </summary>
        public DateTime IssueInstant { get; set; }

        /// <summary>
        /// [Optional]
        /// A URI reference indicating the address to which this request has been sent. This is useful to prevent
        /// malicious forwarding of requests to unintended recipients, a protection that is required by some
        /// protocol bindings. If it is present, the actual recipient MUST check that the URI reference identifies the
        /// location at which the message was received. If it does not, the request MUST be discarded. Some
        /// protocol bindings may require the use of this attribute (see [SAMLBind]).
        /// </summary>
        public EndpointAddress Destination { get; set; }

        /// <summary>
        /// [Optional]
        /// Indicates whether or not (and under what conditions) consent has been obtained from a principal in
        /// the sending of this request. See Section 8.4 for some URI references that MAY be used as the value
        /// of the Consent attribute and their associated descriptions. If no Consent value is provided, the
        /// identifier urn:oasis:names:tc:SAML:2.0:consent:unspecified (see Section 8.4.1) is in effect.
        /// </summary>
        public string Consent { get; set; }

        /// <summary>
        /// [Optional]
        /// Identifies the entity that generated the response message. (For more information on this element, see
        /// Section 2.2.5.)
        /// </summary>
        public EndpointReference Issuer { get; set; }

        protected virtual IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2Constants.ProtocolNamespaceNameX, Saml2Constants.ProtocolNamespace.OriginalString);
            yield return new XAttribute(Saml2Constants.AssertionNamespaceNameX, Saml2Constants.AssertionNamespace.OriginalString);
            yield return new XAttribute(Saml2Constants.Message.Id, Id);
            yield return new XAttribute(Saml2Constants.Message.Version, Version);
            yield return new XAttribute(Saml2Constants.Message.IssueInstant, IssueInstant.ToString("o", CultureInfo.InvariantCulture));

            if (!string.IsNullOrWhiteSpace(Consent))
            {
                yield return new XAttribute(Saml2Constants.Message.Consent, Consent);
            }

            if (Destination != null)
            {
                yield return new XAttribute(Saml2Constants.Message.Destination, Destination);
            }

            if (Issuer != null)
            {
                yield return new XElement(Saml2Constants.AssertionNamespaceX + Saml2Constants.Message.Issuer, Issuer.Uri.OriginalString);
            }
        }

        public abstract XmlDocument ToXml();


        private static System.Security.Cryptography.SymmetricAlgorithm GetKeyInstance(string algorithm)
        {
            System.Security.Cryptography.SymmetricAlgorithm result;
            switch (algorithm)
            {
                case System.Security.Cryptography.Xml.EncryptedXml.XmlEncTripleDESUrl:
                    result = System.Security.Cryptography.TripleDES.Create();
                    break;
                case System.Security.Cryptography.Xml.EncryptedXml.XmlEncAES128Url:
                    result = new System.Security.Cryptography.RijndaelManaged();
                    result.KeySize = 128;
                    break;
                case System.Security.Cryptography.Xml.EncryptedXml.XmlEncAES192Url:
                    result = new System.Security.Cryptography.RijndaelManaged();
                    result.KeySize = 192;
                    break;
                case System.Security.Cryptography.Xml.EncryptedXml.XmlEncAES256Url:
                    result = new System.Security.Cryptography.RijndaelManaged();
                    result.KeySize = 256;
                    break;
                default:
                    result = new System.Security.Cryptography.RijndaelManaged();
                    result.KeySize = 256;
                    break;
            }
            return result;
        }

        internal virtual void Read(string xml, bool validateXmlSignature = false, TimeSpan? clockTolerance = null)
        {
#if DEBUG
            Debug.WriteLine("Saml2P: " + xml);
#endif
            
            XmlDocument = xml.ToXmlDocument();

            if (XmlDocument.DocumentElement.NamespaceURI != Saml2Constants.ProtocolNamespace.OriginalString)
            {
                throw new Saml2ResponseException("Not SAML2 Protocol.");
            }

            ValidateElementName();

            Id = new Saml2Id(XmlDocument.DocumentElement.Attributes[Saml2Constants.Message.Id].GetValueOrNull());

            Version = XmlDocument.DocumentElement.Attributes[Saml2Constants.Message.Version].GetValueOrNull();
            if (Version != Saml2Constants.VersionNumber)
            {
                throw new Saml2ResponseException("Invalid SAML2 version.");
            }

            IssueInstant = DateTime.Parse(XmlDocument.DocumentElement.Attributes[Saml2Constants.Message.IssueInstant].GetValueOrNull(), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal);

            var issuerString = XmlDocument.DocumentElement[Saml2Constants.Message.Issuer, Saml2Constants.AssertionNamespace.OriginalString].GetTextOrNull();
            if (!string.IsNullOrEmpty(issuerString))
            {
                Issuer = new EndpointReference(issuerString);
            }

            var destinationString = XmlDocument.DocumentElement.Attributes[Saml2Constants.Message.Destination].GetValueOrNull();
            if (!string.IsNullOrEmpty(destinationString))
            {
                Destination = new EndpointAddress(destinationString);
            }
        }

        protected abstract void ValidateElementName();

    }
}
