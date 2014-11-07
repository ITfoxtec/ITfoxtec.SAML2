using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace ITfoxtec.Saml2.Schemas.Metadata
{
    /// <summary>
    /// The SPSSODescriptor element extends SSODescriptorType with content reflecting profiles specific
    /// to service providers. 
    /// 
    /// The SSODescriptorType abstract type is a common base type for the concrete types
    /// SPSSODescriptorType and IDPSSODescriptorType, described in subsequent sections. It extends
    /// RoleDescriptorType with elements reflecting profiles common to both identity providers and service
    /// providers that support SSO,
    /// </summary>
    public class SPSsoDescriptor
    {
        const string elementName = Saml2MetadataConstants.Message.SPSsoDescriptor;
        /// <summary>
        /// A whitespace-delimited set of URIs that identify the set of protocol specifications supported by the
        /// role element. For SAML V2.0 entities, this set MUST include the SAML protocol namespace URI,
        /// urn:oasis:names:tc:SAML:2.0:protocol. 
        /// </summary>
        string protocolSupportEnumeration = Saml2Constants.ProtocolNamespace.OriginalString;

        public SPSsoDescriptor(X509Certificate2 signingCertificate = null, X509Certificate2 encryptionCertificate = null)
        {
            SigningCertificate = signingCertificate;
            EncryptionCertificate = encryptionCertificate;
            CertificateIncludeOption = X509IncludeOption.EndCertOnly;
        }

        /// <summary>
        /// [Optional]
        /// Optional attribute that indicates whether the samlp:AuthnRequest messages sent by this
        /// service provider will be signed. If omitted, the value is assumed to be false.
        /// </summary>
        public bool? AuthnRequestsSigned { get; set; }

        /// <summary>
        /// [Optional]
        /// Optional attribute that indicates a requirement for the saml:Assertion elements received by
        /// this service provider to be signed. If omitted, the value is assumed to be false. This requirement
        /// is in addition to any requirement for signing derived from the use of a particular profile/binding
        /// combination.
        /// </summary>
        public bool? WantAssertionsSigned { get; set; }

        /// <summary>
        /// [Optional]
        /// Signing Certificate for Key Descriptor
        /// </summary>
        public X509Certificate2 SigningCertificate { get; internal set; }

        /// <summary>
        /// [Optional]
        /// Encryption Certificate for Key Descriptor
        /// </summary>
        public X509Certificate2 EncryptionCertificate { get; internal set; }

        /// <summary>
        /// [Optional]
        /// Default EndCertOnly (Only the end certificate is included in the X.509 chain information).
        /// </summary>
        public X509IncludeOption CertificateIncludeOption { get; set; }
        
        /// <summary>
        /// [Optional]
        /// Zero or one element of type EndpointType that describe endpoints that support the Single
        /// Logout profiles defined in [SAMLProf].
        /// </summary>
        public SingleLogoutService SingleLogoutService { get; set; }

        /// <summary>
        /// [Optional]
        /// Zero or one element of type anyURI that enumerate the name identifier formats supported by
        /// this system entity acting in this role. See Section 8.3 of [SAMLCore] for some possible values for
        /// this element.
        /// </summary>
        public Uri NameIDFormat { get; set; }

        /// <summary>
        /// [Required]
        /// One element that describe indexed endpoints that support the profiles of the
        /// Authentication Request protocol defined in [SAMLProf]. All service providers support at least one
        /// such endpoint, by definition.
        /// </summary>
        public AssertionConsumerService AssertionConsumerService { get; set; }

        /// <summary>
        /// [Optional]
        /// Zero or one element that describe an application or service provided by the service provider
        /// that requires or desires the use of SAML attributes.
        /// </summary>
        public AttributeConsumingService AttributeConsumingService { get; set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2MetadataConstants.Message.ProtocolSupportEnumeration, protocolSupportEnumeration);

            if(AuthnRequestsSigned.HasValue)
            {
                yield return new XAttribute(Saml2MetadataConstants.Message.AuthnRequestsSigned, AuthnRequestsSigned.Value);
            }

            if (WantAssertionsSigned.HasValue)
            {
                yield return new XAttribute(Saml2MetadataConstants.Message.WantAssertionsSigned, WantAssertionsSigned.Value);
            }

            if (SigningCertificate != null)
            {
                yield return KeyDescriptor(SigningCertificate, KeyTypes.Signing);
            }

            if (EncryptionCertificate != null)
            {
                yield return KeyDescriptor(EncryptionCertificate, KeyTypes.Encryption);
            }
            
            if (SingleLogoutService != null)
            {
                yield return SingleLogoutService.ToXElement();
            }

            if (NameIDFormat != null)
            {
                yield return new XElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.NameIDFormat, NameIDFormat.OriginalString);
            }

            if (AssertionConsumerService == null)
            {
                throw new ArgumentNullException("AssertionConsumerService property");
            }
            yield return AssertionConsumerService.ToXElement();

            if (AttributeConsumingService != null)
            {
                yield return AttributeConsumingService.ToXElement();
            }
        }

        private XObject KeyDescriptor(X509Certificate2 certificate, string keyType)
        {
            KeyInfo keyinfo = new KeyInfo();
            keyinfo.AddClause(new KeyInfoX509Data(certificate, CertificateIncludeOption));

            return new XElement(Saml2MetadataConstants.MetadataNamespaceX + Saml2MetadataConstants.Message.KeyDescriptor, 
                new XAttribute(Saml2MetadataConstants.Message.Use, keyType), 
                XElement.Parse(keyinfo.GetXml().OuterXml));
        }
    }
}
